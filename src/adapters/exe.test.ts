import { describe, it, expect, vi, beforeEach } from 'vitest';
import { exeDefaults } from './exe.js';
import { PolicyDefinitionSchema } from '../policies/schema.js';
import { serializePolicy } from '../policies/serialize.js';

// Mock child_process — scoped to this file so it doesn't affect other adapter tests
const mockExecFile = vi.hoisted(() => vi.fn());
vi.mock('node:child_process', () => ({ execFile: mockExecFile }));

// ── Wire-format helpers ───────────────────────────────────────
//
// The exe adapter wraps every command in a marker-protocol script that
// base64-encodes both the input command and the captured stdout/stderr/exit.
// These helpers reproduce that wire format for unit testing.

const MARKER_OUT = '__AGENTSH_EXE_OUT__';
const MARKER_ERR = '__AGENTSH_EXE_ERR__';
const MARKER_EXIT = '__AGENTSH_EXE_EXIT__=';

/** Build the wire-format marker string the adapter expects from the SSH gateway. */
function buildMarkerOutput(stdout: string, stderr: string, exitCode: number): string {
  const outB64 = Buffer.from(stdout, 'utf-8').toString('base64');
  const errB64 = Buffer.from(stderr, 'utf-8').toString('base64');
  return `${MARKER_OUT}${outB64}${MARKER_ERR}${errB64}${MARKER_EXIT}${exitCode}\n`;
}

/** Extract and decode the user command from a wrapped SSH arg. */
function extractInnerCommand(sshLastArg: string): string {
  const m = sshLastArg.match(/__CMD__="([A-Za-z0-9+/=]+)"/);
  if (!m) throw new Error(`no __CMD__ in arg: ${sshLastArg.slice(0, 200)}`);
  return Buffer.from(m[1], 'base64').toString('utf-8');
}

describe('exe adapter', () => {
  let exe: typeof import('./exe.js').exe;
  beforeEach(async () => {
    mockExecFile.mockReset();
    const mod = await import('./exe.js');
    exe = mod.exe;
  });

  /**
   * Mock the SSH gateway response: format stdout/stderr/exitCode as the
   * marker protocol the adapter expects, then return it via execFile.
   * The SSH process itself always exits 0 when the wrapper ran successfully —
   * the inner exit code lives inside the marker payload.
   */
  function setupMock(stdout = '', stderr = '', exitCode = 0) {
    const wireOutput = buildMarkerOutput(stdout, stderr, exitCode);
    mockExecFile.mockImplementation(
      (_cmd: string, _args: string[], _opts: any, cb?: Function) => {
        const callback = typeof _opts === 'function' ? _opts : cb;
        process.nextTick(() => callback?.(null, wireOutput, ''));
        return {} as any;
      },
    );
  }

  /**
   * Mock an SSH-level failure (gateway/network/timeout) where the wrapper
   * never runs, so no markers appear in the output.
   */
  function setupSshFailure(stderr = 'ssh: connection refused', code = 255) {
    mockExecFile.mockImplementation(
      (_cmd: string, _args: string[], _opts: any, cb?: Function) => {
        const callback = typeof _opts === 'function' ? _opts : cb;
        const err: any = new Error(`exit ${code}`);
        err.code = code;
        err.stdout = '';
        err.stderr = stderr;
        process.nextTick(() => callback?.(err, '', stderr));
        return {} as any;
      },
    );
  }

  it('routes exec through SSH gateway', async () => {
    setupMock('hello\n');
    const adapter = exe('my-vm');
    const result = await adapter.exec('echo', ['hello']);
    expect(mockExecFile).toHaveBeenCalledWith(
      'ssh',
      expect.arrayContaining(['exe.dev']),
      expect.anything(),
      expect.any(Function),
    );
    expect(result.stdout).toBe('hello\n');
    expect(result.exitCode).toBe(0);
  });

  it('wraps gateway command in single quotes around the marker script', async () => {
    setupMock('');
    const adapter = exe('test-vm');
    await adapter.exec('echo', ['hello world']);
    const args = mockExecFile.mock.calls[0][1] as string[];
    const lastArg = args[args.length - 1];
    expect(lastArg).toMatch(/^ssh test-vm '.*'$/);
    expect(lastArg).toContain('__CMD__=');
  });

  it('drops sudo prefix because exe.dev VMs are always root', async () => {
    setupMock('');
    const adapter = exe('my-vm');
    await adapter.exec('chmod', ['755', '/tmp/x'], { sudo: true });
    const args = mockExecFile.mock.calls[0][1] as string[];
    const inner = extractInnerCommand(args[args.length - 1]);
    // The default exe.dev ubuntu:22.04 image has no sudo binary, and we're
    // already root — so opts.sudo must be elided, not honored.
    expect(inner).not.toContain('sudo');
    expect(inner).toContain('chmod');
  });

  it('wraps cwd with cd command', async () => {
    setupMock('');
    const adapter = exe('my-vm');
    await adapter.exec('ls', [], { cwd: '/workspace' });
    const args = mockExecFile.mock.calls[0][1] as string[];
    const inner = extractInnerCommand(args[args.length - 1]);
    expect(inner).toContain("cd '/workspace'");
  });

  it('detached returns immediately with exitCode 0', async () => {
    setupMock('');
    const adapter = exe('my-vm');
    const result = await adapter.exec('server', ['start'], { detached: true });
    expect(result.exitCode).toBe(0);
    expect(result.stdout).toBe('');
  });

  it('includes env vars in command', async () => {
    setupMock('');
    const adapter = exe('my-vm');
    await adapter.exec('agentsh', ['exec'], { env: { TRACEPARENT: '00-abc-def-01' } });
    const args = mockExecFile.mock.calls[0][1] as string[];
    const inner = extractInnerCommand(args[args.length - 1]);
    expect(inner).toContain('TRACEPARENT=');
  });

  it('writeFile uses base64 approach', async () => {
    setupMock('');
    const adapter = exe('my-vm');
    await adapter.writeFile('/workspace/test.txt', 'hello');
    const args = mockExecFile.mock.calls[0][1] as string[];
    const inner = extractInnerCommand(args[args.length - 1]);
    expect(inner).toContain('base64 -d');
    // 'hello' base64-encoded is 'aGVsbG8='
    expect(inner).toContain('aGVsbG8=');
  });

  it('readFile uses cat', async () => {
    setupMock('file content');
    const adapter = exe('my-vm');
    const content = await adapter.readFile('/workspace/test.txt');
    const args = mockExecFile.mock.calls[0][1] as string[];
    const inner = extractInnerCommand(args[args.length - 1]);
    expect(inner).toContain('cat');
    expect(content).toBe('file content');
  });

  it('writeFile throws on non-zero exit', async () => {
    setupMock('', 'permission denied', 1);
    const adapter = exe('my-vm');
    await expect(adapter.writeFile('/etc/test', 'data')).rejects.toThrow('writeFile failed');
  });

  it('readFile throws on non-zero exit', async () => {
    setupMock('', 'no such file', 1);
    const adapter = exe('my-vm');
    await expect(adapter.readFile('/missing')).rejects.toThrow('readFile failed');
  });

  it('exec returns error info on non-zero exit', async () => {
    setupMock('', 'command not found', 127);
    const adapter = exe('my-vm');
    const result = await adapter.exec('nonexistent', []);
    expect(result.exitCode).toBe(127);
    expect(result.stderr).toBe('command not found');
  });

  it('exec surfaces SSH-level failures with non-zero exit', async () => {
    setupSshFailure('ssh: Could not resolve hostname', 255);
    const adapter = exe('my-vm');
    const result = await adapter.exec('echo', ['hi']);
    expect(result.exitCode).toBe(255);
    expect(result.stderr).toContain('Could not resolve hostname');
  });

  it('stop is a no-op', async () => {
    const adapter = exe('my-vm');
    await adapter.stop!();
    expect(mockExecFile).not.toHaveBeenCalled();
  });

  it('fileExists returns true when test -f succeeds', async () => {
    setupMock('');
    const adapter = exe('my-vm');
    expect(await adapter.fileExists!('/usr/bin/agentsh')).toBe(true);
  });

  it('fileExists returns false when test -f fails', async () => {
    setupMock('', '', 1);
    const adapter = exe('my-vm');
    expect(await adapter.fileExists!('/missing')).toBe(false);
  });

  it('filters agentsh noise from stderr', async () => {
    setupMock('ok', 'landlock: initialized\nactual error\nagentsh: starting', 0);
    const adapter = exe('my-vm');
    const result = await adapter.exec('echo', ['ok']);
    expect(result.stderr).toBe('actual error');
    expect(result.stderr).not.toContain('landlock');
  });

  it('preserves stdout content with embedded special characters', async () => {
    const content = 'line1\nline2\ttab\n"quotes" & <brackets>';
    setupMock(content);
    const adapter = exe('my-vm');
    const result = await adapter.exec('cat', ['/tmp/x']);
    expect(result.stdout).toBe(content);
  });

  it('survives single quotes in the user command', async () => {
    setupMock("it's working\n");
    const adapter = exe('my-vm');
    const result = await adapter.exec('sh', ['-c', "echo \"it's working\""]);
    const args = mockExecFile.mock.calls[0][1] as string[];
    const lastArg = args[args.length - 1];
    // The wrapped command must be safe for the gateway shell — only one set
    // of single quotes around the wrapper, with no inner single quotes.
    const wrapped = lastArg.match(/^ssh my-vm '(.*)'$/s)?.[1];
    expect(wrapped).toBeDefined();
    expect(wrapped).not.toContain("'");
    // And the inner command, once decoded, must round-trip the user's intent.
    // The single quote inside the arg gets shell-escaped as '\'' (close-quote,
    // escaped quote, re-open), which is what the inner shell will eval back to
    // a literal `'`. Round-tripping means the final shell executes the right
    // thing — not that the encoded string is byte-identical to the input.
    const inner = extractInnerCommand(lastArg);
    expect(inner).toContain("echo \"it'\\''s working\"");
    expect(result.stdout).toBe("it's working\n");
  });
});

describe('exeDefaults', () => {
  it('returns an object with policy', () => {
    const defaults = exeDefaults();
    expect(defaults).toBeDefined();
    expect(defaults.policy).toBeDefined();
  });

  it('policy validates against PolicyDefinitionSchema', () => {
    const { policy } = exeDefaults();
    const result = PolicyDefinitionSchema.safeParse(policy);
    expect(result.success).toBe(true);
  });

  it('policy serializes to valid YAML', () => {
    const { policy } = exeDefaults();
    if (policy) {
      const yaml = serializePolicy(policy);
      expect(yaml).toBeTruthy();
      expect(typeof yaml).toBe('string');
    }
  });

  it('blocks exe.dev internals (shelley)', () => {
    const { policy } = exeDefaults() as any;
    const denyPaths = policy.file
      .filter((r: any) => 'deny' in r)
      .flatMap((r: any) => Array.isArray(r.deny) ? r.deny : [r.deny]);
    expect(denyPaths).toContain('/usr/bin/shelley');
    expect(denyPaths).toContain('/usr/local/bin/shelley');
  });

  it('includes /root workspace', () => {
    const { policy } = exeDefaults() as any;
    const allPaths = policy.file
      .filter((r: any) => 'allow' in r)
      .flatMap((r: any) => Array.isArray(r.allow) ? r.allow : [r.allow]);
    expect(allPaths).toContain('/root/**');
    expect(allPaths).toContain('/workspace/**');
  });

  it('denies credential paths', () => {
    const { policy } = exeDefaults() as any;
    const denyPaths = policy.file
      .filter((r: any) => 'deny' in r)
      .flatMap((r: any) => Array.isArray(r.deny) ? r.deny : [r.deny]);
    expect(denyPaths).toContain('~/.ssh/**');
    expect(denyPaths).toContain('~/.aws/**');
    expect(denyPaths).toContain('**/.env');
  });

  it('blocks private networks', () => {
    const { policy } = exeDefaults() as any;
    const denyCidrs = policy.network
      .filter((r: any) => 'denyCidrs' in r)
      .flatMap((r: any) => r.denyCidrs);
    expect(denyCidrs).toContain('10.0.0.0/8');
    expect(denyCidrs).toContain('169.254.169.254/32');
  });

  it('blocks exe.dev interference commands', () => {
    const { policy } = exeDefaults() as any;
    const denyCmds = policy.commands
      .filter((r: any) => 'deny' in r)
      .flatMap((r: any) => Array.isArray(r.deny) ? r.deny : [r.deny]);
    expect(denyCmds).toContain('shelley');
    expect(denyCmds).toContain('iptables');
    expect(denyCmds).toContain('sudo');
  });

  it('has soft-delete for workspace', () => {
    const { policy } = exeDefaults() as any;
    const softDeletePaths = policy.file
      .filter((r: any) => 'softDelete' in r)
      .flatMap((r: any) => Array.isArray(r.softDelete) ? r.softDelete : [r.softDelete]);
    expect(softDeletePaths).toContain('/root/**');
    expect(softDeletePaths).toContain('/workspace/**');
  });

  it('has conservative resource limits', () => {
    const { policy } = exeDefaults() as any;
    expect(policy.resourceLimits.maxMemoryMb).toBe(2048);
    expect(policy.resourceLimits.cpuQuotaPercent).toBe(50);
    expect(policy.resourceLimits.pidsMax).toBe(100);
  });

  it('has env policy with blockIteration', () => {
    const { policy } = exeDefaults() as any;
    expect(policy.envPolicy.blockIteration).toBe(true);
    expect(policy.envPolicy.deny).toContain('AWS_*');
    expect(policy.envPolicy.deny).toContain('OPENAI_API_KEY');
  });

  it('has allowDegraded false', () => {
    const defaults = exeDefaults() as any;
    expect(defaults.serverConfig.allowDegraded).toBe(false);
  });
});
