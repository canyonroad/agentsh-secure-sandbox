import { describe, it, expect, vi, beforeEach } from 'vitest';
import { provision } from './provision.js';
import type { SandboxAdapter, ExecResult } from './types.js';
import { ProvisioningError, IntegrityError } from './errors.js';
import { PINNED_VERSION } from './integrity.js';

// ─── Mock adapter helper ──────────────────────────────────────

function ok(stdout = ''): ExecResult {
  return { stdout, stderr: '', exitCode: 0 };
}

function createMockAdapter(
  overrides?: Record<string, ExecResult>,
): SandboxAdapter {
  const responses: Record<string, ExecResult> = {
    'test -f': { stdout: '', stderr: '', exitCode: 1 }, // binary not found by default
    uname: ok('x86_64'),
    curl: ok(),
    'tar xz': ok(),
    sha256sum: ok(
      '89f7ebbfd75ffd961245ec62b2602fd0cc387740502ac858dbc39c367c5699c5',
    ),
    install: ok(),
    'agentsh detect': { stdout: '', stderr: JSON.stringify({ security_mode: 'full' }), exitCode: 0 },
    'agentsh shim': ok(),
    'echo $AGENTSH_SESSION_ID': ok('existing-session-456'),
    mkdir: ok(),
    find: ok(),
    chown: ok(),
    'agentsh server': ok(),
    'curl -sf http://127.0.0.1:18080/health': ok(),
    'agentsh session': ok(
      JSON.stringify({ session_id: 'test-session-123' }),
    ),
    ...overrides,
  };
  return {
    exec: vi.fn(async (cmd: string, args?: string[]) => {
      const fullCmd = [cmd, ...(args ?? [])].join(' ');
      // Match longer keys first to avoid false positives (e.g. "tar" matching "agentsh.tar.gz")
      const sortedKeys = Object.keys(responses).sort(
        (a, b) => b.length - a.length,
      );
      for (const key of sortedKeys) {
        if (fullCmd.includes(key)) return responses[key];
      }
      return ok();
    }),
    writeFile: vi.fn(async () => {}),
    readFile: vi.fn(async () => ''),
  };
}

// ─── Tests ────────────────────────────────────────────────────

describe('provision', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('completes download flow — returns session ID + security mode', async () => {
    const adapter = createMockAdapter();
    const result = await provision(adapter, {});

    expect(result.sessionId).toBe('test-session-123');
    expect(result.securityMode).toBe('full');
  });

  it('skips download when preinstalled and binary exists', async () => {
    const adapter = createMockAdapter({
      'test -f': ok(), // binary found
    });
    const result = await provision(adapter, {
      installStrategy: 'preinstalled',
    });

    expect(result.sessionId).toBe('test-session-123');
    // curl/wget should not have been called for download (health check uses curl too)
    const execCalls = (adapter.exec as ReturnType<typeof vi.fn>).mock.calls;
    const downloadCurlCalls = execCalls.filter(
      ([cmd, args]: [string, string[]]) =>
        cmd === 'curl' && !args?.some((a: string) => a.includes('/health')),
    );
    expect(downloadCurlCalls).toHaveLength(0);
  });

  it('throws when preinstalled but binary not found', async () => {
    const adapter = createMockAdapter({
      'test -f': { stdout: '', stderr: '', exitCode: 1 },
    });

    await expect(
      provision(adapter, { installStrategy: 'preinstalled' }),
    ).rejects.toThrow(ProvisioningError);
  });

  it('writes system policy and user policy', async () => {
    const adapter = createMockAdapter();
    await provision(adapter, {});

    const writeCalls = (adapter.writeFile as ReturnType<typeof vi.fn>).mock
      .calls;

    // System policy
    const systemPolicyCall = writeCalls.find(
      ([path]: [string]) => path === '/etc/agentsh/system/policy.yml',
    );
    expect(systemPolicyCall).toBeDefined();
    expect(systemPolicyCall![1]).toContain('_system-protect-config');

    // User policy
    const userPolicyCall = writeCalls.find(
      ([path]: [string]) => path === '/etc/agentsh/policy.yml',
    );
    expect(userPolicyCall).toBeDefined();
    expect(userPolicyCall![1]).toContain('file_rules');
  });

  it('writes server config', async () => {
    const adapter = createMockAdapter();
    await provision(adapter, { workspace: '/workspace' });

    const writeCalls = (adapter.writeFile as ReturnType<typeof vi.fn>).mock
      .calls;

    const configCall = writeCalls.find(
      ([path]: [string]) => path === '/etc/agentsh/config.yml',
    );
    expect(configCall).toBeDefined();
    expect(configCall![1]).toContain('sandbox');
    expect(configCall![1]).not.toContain('workspace');
  });

  it('sets file permissions (chmod, chown)', async () => {
    const adapter = createMockAdapter();
    await provision(adapter, {});

    const execCalls = (adapter.exec as ReturnType<typeof vi.fn>).mock.calls;

    // find chmod calls
    const findCalls = execCalls.filter(
      ([cmd]: [string]) => cmd === 'find',
    );
    expect(findCalls.length).toBeGreaterThanOrEqual(2);

    // chown call
    const chownCalls = execCalls.filter(
      ([cmd]: [string]) => cmd === 'chown',
    );
    expect(chownCalls.length).toBeGreaterThanOrEqual(1);
    expect(chownCalls[0][1]).toEqual(['-R', 'root:root', '/etc/agentsh/']);
  });

  it('starts server detached with sudo', async () => {
    const adapter = createMockAdapter();
    await provision(adapter, {});

    const execCalls = (adapter.exec as ReturnType<typeof vi.fn>).mock.calls;
    const serverCall = execCalls.find(
      ([cmd, args]: [string, string[]]) =>
        cmd === 'agentsh' && args?.[0] === 'server',
    );
    expect(serverCall).toBeDefined();
    expect(serverCall![2]).toEqual({ detached: true, sudo: true });
  });

  it('throws on health check failure', async () => {
    vi.useFakeTimers();
    const adapter = createMockAdapter({
      'curl -sf http://127.0.0.1:18080/health': { stdout: '', stderr: 'not ready', exitCode: 1 },
    });

    let caughtError: unknown;
    const promise = provision(adapter, {}).catch((e) => {
      caughtError = e;
    });

    // Advance past all 10 health check retries (9 delays of 500ms each)
    for (let i = 0; i < 10; i++) {
      await vi.advanceTimersByTimeAsync(500);
    }

    await promise;
    expect(caughtError).toBeInstanceOf(ProvisioningError);
    expect((caughtError as ProvisioningError).message).toBe(
      'Provisioning failed at phase: startup',
    );
    expect((caughtError as ProvisioningError).stderr).toBe('Health check failed after 10 attempts');

    vi.useRealTimers();
  }, 10000);

  it('throws IntegrityError on checksum mismatch', async () => {
    const adapter = createMockAdapter({
      sha256sum: ok('deadbeefwrongchecksum'),
    });

    await expect(provision(adapter, {})).rejects.toThrow(IntegrityError);
  });

  it('throws when minimum security mode not met', async () => {
    const adapter = createMockAdapter({
      'agentsh detect': { stdout: '', stderr: JSON.stringify({ security_mode: 'minimal' }), exitCode: 0 },
    });

    const p = provision(adapter, { minimumSecurityMode: 'full' });
    await expect(p).rejects.toBeInstanceOf(ProvisioningError);
    await expect(p).rejects.toMatchObject({
      stderr: expect.stringContaining("weaker than required 'full'"),
    });
  });

  it('uses agentDefault policy when none specified', async () => {
    const adapter = createMockAdapter();
    await provision(adapter, {});

    const writeCalls = (adapter.writeFile as ReturnType<typeof vi.fn>).mock
      .calls;
    const userPolicyCall = writeCalls.find(
      ([path]: [string]) => path === '/etc/agentsh/policy.yml',
    );
    expect(userPolicyCall).toBeDefined();
    // agentDefault has workspace file rules and network rules
    expect(userPolicyCall![1]).toContain('/workspace/**');
  });

  it('maps uname x86_64 to linux_amd64', async () => {
    const adapter = createMockAdapter({
      uname: ok('x86_64'),
    });
    const result = await provision(adapter, {});
    expect(result.sessionId).toBe('test-session-123');

    // Verify the curl call used linux_amd64 URL
    const execCalls = (adapter.exec as ReturnType<typeof vi.fn>).mock.calls;
    const curlCall = execCalls.find(
      ([cmd]: [string]) => cmd === 'curl',
    );
    expect(curlCall).toBeDefined();
    const curlArgs = curlCall![1] as string[];
    const urlArg = curlArgs.find((a: string) => a.includes('agentsh_'));
    expect(urlArg).toContain('linux_amd64');
  });

  it('maps uname aarch64 to linux_arm64', async () => {
    const adapter = createMockAdapter({
      uname: ok('aarch64'),
      sha256sum: ok(
        '3fabbd749f9e98fb9f96ddfc94c389a6868cda7ed3668daa8440c39ceec85f3b',
      ),
    });
    const result = await provision(adapter, {});
    expect(result.sessionId).toBe('test-session-123');

    // Verify the curl call used linux_arm64 URL
    const execCalls = (adapter.exec as ReturnType<typeof vi.fn>).mock.calls;
    const curlCall = execCalls.find(
      ([cmd]: [string]) => cmd === 'curl',
    );
    expect(curlCall).toBeDefined();
    const curlArgs = curlCall![1] as string[];
    const urlArg = curlArgs.find((a: string) => a.includes('agentsh_'));
    expect(urlArg).toContain('linux_arm64');
  });

  it('does not pass workspace to config (workspace is a session create arg)', async () => {
    const adapter = createMockAdapter();
    await provision(adapter, { workspace: '/home/daytona' });

    const writeCalls = (adapter.writeFile as ReturnType<typeof vi.fn>).mock
      .calls;
    const configCall = writeCalls.find(
      ([path]: [string]) => path === '/etc/agentsh/config.yml',
    );
    expect(configCall).toBeDefined();
    expect(configCall![1]).not.toContain('/home/daytona');
  });

  it('passes watchtower to config', async () => {
    const adapter = createMockAdapter();
    await provision(adapter, {
      watchtower: 'https://watchtower.example.com',
    });

    const writeCalls = (adapter.writeFile as ReturnType<typeof vi.fn>).mock
      .calls;
    const configCall = writeCalls.find(
      ([path]: [string]) => path === '/etc/agentsh/config.yml',
    );
    expect(configCall).toBeDefined();
    expect(configCall![1]).toContain('watchtower.example.com');
  });

  it('auto-enables realPaths when security mode has FUSE (full)', async () => {
    const adapter = createMockAdapter({
      'agentsh detect': { stdout: '', stderr: JSON.stringify({ security_mode: 'full' }), exitCode: 0 },
    });
    await provision(adapter, {});

    const writeCalls = (adapter.writeFile as ReturnType<typeof vi.fn>).mock.calls;
    const configCall = writeCalls.find(
      ([path]: [string]) => path === '/etc/agentsh/config.yml',
    );
    expect(configCall).toBeDefined();
    expect(configCall![1]).toContain('real_paths');
  });

  it('auto-enables realPaths when security mode is landlock (FUSE)', async () => {
    const adapter = createMockAdapter({
      'agentsh detect': { stdout: '', stderr: JSON.stringify({ security_mode: 'landlock' }), exitCode: 0 },
    });
    await provision(adapter, {});

    const writeCalls = (adapter.writeFile as ReturnType<typeof vi.fn>).mock.calls;
    const configCall = writeCalls.find(
      ([path]: [string]) => path === '/etc/agentsh/config.yml',
    );
    expect(configCall).toBeDefined();
    expect(configCall![1]).toContain('real_paths');
  });

  it('does not auto-enable realPaths for minimal mode (no FUSE)', async () => {
    const adapter = createMockAdapter({
      'agentsh detect': { stdout: '', stderr: JSON.stringify({ security_mode: 'minimal' }), exitCode: 0 },
    });
    await provision(adapter, {});

    const writeCalls = (adapter.writeFile as ReturnType<typeof vi.fn>).mock.calls;
    const configCall = writeCalls.find(
      ([path]: [string]) => path === '/etc/agentsh/config.yml',
    );
    expect(configCall).toBeDefined();
    expect(configCall![1]).not.toContain('real_paths');
  });

  it('respects explicit realPaths=false even with FUSE', async () => {
    const adapter = createMockAdapter({
      'agentsh detect': { stdout: '', stderr: JSON.stringify({ security_mode: 'full' }), exitCode: 0 },
    });
    await provision(adapter, { realPaths: false });

    const writeCalls = (adapter.writeFile as ReturnType<typeof vi.fn>).mock.calls;
    const configCall = writeCalls.find(
      ([path]: [string]) => path === '/etc/agentsh/config.yml',
    );
    expect(configCall).toBeDefined();
    expect(configCall![1]).not.toContain('real_paths');
  });

  // ─── 'running' install strategy ─────────────────────────────

  it('running strategy reads existing session from env and returns passthrough', async () => {
    const adapter = createMockAdapter();
    const result = await provision(adapter, { installStrategy: 'running' });

    expect(result.sessionId).toBe('existing-session-456');
    expect(result.securityMode).toBe('full');
    expect(result.passthrough).toBe(true);

    const execCalls = (adapter.exec as ReturnType<typeof vi.fn>).mock.calls;

    // Should NOT call install, shim, server start, or session create
    const shimCalls = execCalls.filter(
      ([cmd, args]: [string, string[]]) =>
        cmd === 'agentsh' && args?.[0] === 'shim',
    );
    expect(shimCalls).toHaveLength(0);

    const serverCalls = execCalls.filter(
      ([cmd, args]: [string, string[]]) =>
        cmd === 'agentsh' && args?.[0] === 'server',
    );
    expect(serverCalls).toHaveLength(0);

    const sessionCalls = execCalls.filter(
      ([cmd, args]: [string, string[]]) =>
        cmd === 'agentsh' && args?.[0] === 'session',
    );
    expect(sessionCalls).toHaveLength(0);

    // Should NOT write any files
    expect(adapter.writeFile).not.toHaveBeenCalled();

    // Should NOT call detect (skipped for 'running' strategy)
    const detectCalls = execCalls.filter(
      ([cmd, args]: [string, string[]]) =>
        cmd === 'agentsh' && args?.[0] === 'detect',
    );
    expect(detectCalls).toHaveLength(0);
  });

  it('running strategy throws when AGENTSH_SESSION_ID is not set', async () => {
    const adapter = createMockAdapter({
      'echo $AGENTSH_SESSION_ID': ok(''),
    });

    await expect(
      provision(adapter, { installStrategy: 'running' }),
    ).rejects.toMatchObject({
      stderr: expect.stringContaining('AGENTSH_SESSION_ID not set'),
    });
  });

  it('running strategy still enforces minimum security mode', async () => {
    const adapter = createMockAdapter();

    await expect(
      provision(adapter, {
        installStrategy: 'running',
        securityMode: 'minimal',
        minimumSecurityMode: 'full',
      }),
    ).rejects.toMatchObject({
      stderr: expect.stringContaining("weaker than required 'full'"),
    });
  });

  it('running strategy respects securityMode override', async () => {
    const adapter = createMockAdapter();
    const result = await provision(adapter, {
      installStrategy: 'running',
      securityMode: 'landlock',
    });

    expect(result.securityMode).toBe('landlock');
    expect(result.passthrough).toBe(true);
  });

  it('running strategy respects sessionId override', async () => {
    const adapter = createMockAdapter({
      'echo $AGENTSH_SESSION_ID': ok(''),  // env var not set
    });
    const result = await provision(adapter, {
      installStrategy: 'running',
      sessionId: 'explicit-session-789',
    });

    expect(result.sessionId).toBe('explicit-session-789');
    expect(result.passthrough).toBe(true);
  });

  it('running strategy still performs health check', async () => {
    const adapter = createMockAdapter();
    await provision(adapter, { installStrategy: 'running' });

    const execCalls = (adapter.exec as ReturnType<typeof vi.fn>).mock.calls;
    const healthCalls = execCalls.filter(
      ([cmd, args]: [string, string[]]) =>
        cmd === 'curl' && args?.some((a: string) => a.includes('/health')),
    );
    expect(healthCalls.length).toBeGreaterThanOrEqual(1);
  });

  it('throws on unknown security mode from detect', async () => {
    const adapter = createMockAdapter({
      'agentsh detect': { stdout: '', stderr: JSON.stringify({ security_mode: 'unknown_mode' }), exitCode: 0 },
    });

    await expect(provision(adapter, {})).rejects.toMatchObject({
      stderr: expect.stringContaining("Unknown security mode: 'unknown_mode'"),
    });
  });

  it('upload strategy uploads tarball and extracts all binaries', async () => {
    const mockFetch = vi.fn(async () => ({
      ok: true,
      arrayBuffer: async () => new ArrayBuffer(8),
    }));
    vi.stubGlobal('fetch', mockFetch);

    try {
      const adapter = createMockAdapter();
      const result = await provision(adapter, { installStrategy: 'upload' });

      expect(result.sessionId).toBe('test-session-123');

      // Should have written tarball via adapter.writeFile
      const writeCalls = (adapter.writeFile as ReturnType<typeof vi.fn>).mock.calls;
      const tarballWrite = writeCalls.find(
        ([path]: [string]) => path === '/tmp/agentsh.tar.gz',
      );
      expect(tarballWrite).toBeDefined();

      // Should have called tar to extract
      const execCalls = (adapter.exec as ReturnType<typeof vi.fn>).mock.calls;
      const tarCalls = execCalls.filter(
        ([cmd]: [string]) => cmd === 'tar',
      );
      expect(tarCalls.length).toBeGreaterThanOrEqual(1);

      // Should have installed all three binaries
      const installCalls = execCalls.filter(
        ([cmd]: [string]) => cmd === 'install',
      );
      const installedDests = installCalls.map(
        ([, args]: [string, string[]]) => args[args.length - 1],
      );
      expect(installedDests).toContain('/usr/local/bin/agentsh');
      expect(installedDests).toContain('/usr/bin/agentsh-shell-shim');
      expect(installedDests).toContain('/usr/local/bin/agentsh-unixwrap');
    } finally {
      vi.unstubAllGlobals();
    }
  });
});
