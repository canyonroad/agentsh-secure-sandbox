import { describe, it, expect, vi, beforeEach } from 'vitest';
import { secureSandbox, createSandbox } from './api.js';
import type { SandboxAdapter } from './core/types.js';
import { MissingPeerDependencyError } from './core/errors.js';

// ─── Full mock adapter for end-to-end provisioning ──────────

function createFullMockAdapter(): SandboxAdapter {
  return {
    exec: vi.fn(async (cmd: string, args?: string[]) => {
      const full = [cmd, ...(args ?? [])].join(' ');
      if (full.includes('test -f'))
        return { stdout: '', stderr: '', exitCode: 1 };
      if (full.includes('uname'))
        return { stdout: 'x86_64', stderr: '', exitCode: 0 };
      if (full.includes('sha256sum'))
        return {
          stdout:
            '2ab8ba0d6637fe1a5badf840c3db197161a6f9865d721ed216029d229b1b9bbc',
          stderr: '',
          exitCode: 0,
        };
      if (full.includes('agentsh detect'))
        return {
          stdout: '',
          stderr: JSON.stringify({ security_mode: 'full' }),
          exitCode: 0,
        };
      if (full.includes('agentsh session create'))
        return {
          stdout: JSON.stringify({ session_id: 'sid-test' }),
          stderr: '',
          exitCode: 0,
        };
      return { stdout: '', stderr: '', exitCode: 0 };
    }),
    writeFile: vi.fn(async () => {}),
    readFile: vi.fn(async () => ''),
    stop: vi.fn(async () => {}),
  };
}

// ─── Tests ──────────────────────────────────────────────────

describe('secureSandbox', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('returns a SecuredSandbox with sessionId and securityMode', async () => {
    const adapter = createFullMockAdapter();
    const sandbox = await secureSandbox(adapter);
    expect(sandbox.sessionId).toBe('sid-test');
    expect(sandbox.securityMode).toBe('full');
    expect(typeof sandbox.exec).toBe('function');
    expect(typeof sandbox.writeFile).toBe('function');
    expect(typeof sandbox.readFile).toBe('function');
    expect(typeof sandbox.stop).toBe('function');
  });

  it('uses agentDefault policy when none specified', async () => {
    const adapter = createFullMockAdapter();
    await secureSandbox(adapter);
    const writeFileCalls = (adapter.writeFile as any).mock.calls;
    const policyWrite = writeFileCalls.find(
      (c: any) => c[0] === '/etc/agentsh/policy.yml',
    );
    expect(policyWrite![1]).toContain('registry.npmjs.org');
  });

  it('validates custom policy — throws on invalid', async () => {
    const adapter = createFullMockAdapter();
    await expect(
      secureSandbox(adapter, {
        policy: { file: [{ invalid: true }] } as any,
      }),
    ).rejects.toThrow();
  });

  it('runtime exec goes through agentsh', async () => {
    const adapter = createFullMockAdapter();
    const sandbox = await secureSandbox(adapter);
    await sandbox.exec('ls');
    const lastExecCall = (adapter.exec as any).mock.calls.at(-1);
    expect(lastExecCall[0]).toBe('agentsh');
    expect(lastExecCall[1]).toContain('exec');
  });
});

describe('createSandbox', () => {
  it('throws MissingPeerDependencyError when @vercel/sandbox not installed', async () => {
    // Mock the dynamic import to simulate missing package
    vi.doMock('@vercel/sandbox', () => {
      throw new Error('Cannot find module');
    });
    // Re-import api to pick up the mock
    const { createSandbox: create } = await import('./api.js');
    await expect(create()).rejects.toThrow(MissingPeerDependencyError);
    vi.doUnmock('@vercel/sandbox');
  });
});
