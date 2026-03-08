import { describe, it, expect, vi, beforeEach } from 'vitest';
import { secureSandbox } from './api.js';
import type { SandboxAdapter } from './core/types.js';

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
            '89f7ebbfd75ffd961245ec62b2602fd0cc387740502ac858dbc39c367c5699c5',
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
