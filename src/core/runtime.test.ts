import { describe, it, expect, vi } from 'vitest';
import { createSecuredSandbox } from './runtime.js';
import type { SandboxAdapter } from './types.js';
import { RuntimeError } from './errors.js';

function createMockAdapter(): SandboxAdapter {
  return {
    exec: vi.fn(async () => ({ stdout: '', stderr: '', exitCode: 0 })),
    writeFile: vi.fn(async () => {}),
    readFile: vi.fn(async () => ''),
    stop: vi.fn(async () => {}),
  };
}

describe('SecuredSandbox', () => {
  describe('exec', () => {
    it('routes through agentsh exec with session ID', async () => {
      const adapter = createMockAdapter();
      const sandbox = createSecuredSandbox(adapter, 'sid-123', 'full');
      await sandbox.exec('ls /workspace');
      expect(adapter.exec).toHaveBeenCalledWith(
        'agentsh',
        [
          'exec',
          '--output',
          'json',
          'sid-123',
          '--',
          'bash',
          '-c',
          'ls /workspace',
        ],
        undefined,
      );
    });

    it('passes cwd option', async () => {
      const adapter = createMockAdapter();
      const sandbox = createSecuredSandbox(adapter, 'sid-123', 'full');
      await sandbox.exec('ls', { cwd: '/workspace/src' });
      expect(adapter.exec).toHaveBeenCalledWith(
        'agentsh',
        expect.anything(),
        { cwd: '/workspace/src' },
      );
    });

    it('returns ExecResult from agentsh', async () => {
      const adapter = createMockAdapter();
      (adapter.exec as ReturnType<typeof vi.fn>).mockResolvedValue({
        stdout: 'file1.ts',
        stderr: '',
        exitCode: 0,
      });
      const sandbox = createSecuredSandbox(adapter, 'sid-123', 'full');
      const result = await sandbox.exec('ls');
      expect(result.stdout).toBe('file1.ts');
      expect(result.exitCode).toBe(0);
    });

    it('returns denial as structured result, does NOT throw', async () => {
      const adapter = createMockAdapter();
      (adapter.exec as ReturnType<typeof vi.fn>).mockResolvedValue({
        stdout: '',
        stderr: 'denied by policy',
        exitCode: 1,
      });
      const sandbox = createSecuredSandbox(adapter, 'sid-123', 'full');
      const result = await sandbox.exec('env');
      expect(result.exitCode).toBe(1);
      expect(result.stderr).toContain('denied');
    });

    it('throws RuntimeError on transport failure', async () => {
      const adapter = createMockAdapter();
      (adapter.exec as ReturnType<typeof vi.fn>).mockResolvedValue({
        stdout: '',
        stderr: 'agentsh: command not found',
        exitCode: 127,
      });
      const sandbox = createSecuredSandbox(adapter, 'sid-123', 'full');
      await expect(sandbox.exec('ls')).rejects.toThrow(RuntimeError);
    });
  });

  describe('writeFile', () => {
    it('routes through agentsh exec with base64 content', async () => {
      const adapter = createMockAdapter();
      const sandbox = createSecuredSandbox(adapter, 'sid-123', 'full');
      const result = await sandbox.writeFile('/workspace/test.txt', 'hello');
      expect(result.success).toBe(true);
      expect(result.path).toBe('/workspace/test.txt');
      expect(adapter.exec).toHaveBeenCalledWith(
        'agentsh',
        expect.arrayContaining(['exec', 'sid-123']),
      );
    });

    it('returns failure on policy denial', async () => {
      const adapter = createMockAdapter();
      (adapter.exec as ReturnType<typeof vi.fn>).mockResolvedValue({
        stdout: '',
        stderr: 'denied by policy',
        exitCode: 1,
      });
      const sandbox = createSecuredSandbox(adapter, 'sid-123', 'full');
      const result = await sandbox.writeFile('/etc/passwd', 'evil');
      expect(result.success).toBe(false);
      if (!result.success) expect(result.error).toContain('denied');
    });

    it('throws RuntimeError on transport failure', async () => {
      const adapter = createMockAdapter();
      (adapter.exec as ReturnType<typeof vi.fn>).mockResolvedValue({
        stdout: '',
        stderr: 'agentsh: not found',
        exitCode: 127,
      });
      const sandbox = createSecuredSandbox(adapter, 'sid-123', 'full');
      await expect(
        sandbox.writeFile('/workspace/x', 'y'),
      ).rejects.toThrow(RuntimeError);
    });
  });

  describe('readFile', () => {
    it('returns content on success', async () => {
      const adapter = createMockAdapter();
      (adapter.exec as ReturnType<typeof vi.fn>).mockResolvedValue({
        stdout: 'file contents',
        stderr: '',
        exitCode: 0,
      });
      const sandbox = createSecuredSandbox(adapter, 'sid-123', 'full');
      const result = await sandbox.readFile('/workspace/test.txt');
      expect(result.success).toBe(true);
      if (result.success) expect(result.content).toBe('file contents');
    });

    it('returns failure on denial', async () => {
      const adapter = createMockAdapter();
      (adapter.exec as ReturnType<typeof vi.fn>).mockResolvedValue({
        stdout: '',
        stderr: 'denied',
        exitCode: 1,
      });
      const sandbox = createSecuredSandbox(adapter, 'sid-123', 'full');
      const result = await sandbox.readFile('~/.ssh/id_rsa');
      expect(result.success).toBe(false);
    });
  });

  describe('stop', () => {
    it('calls adapter.stop if available', async () => {
      const adapter = createMockAdapter();
      const sandbox = createSecuredSandbox(adapter, 'sid-123', 'full');
      await sandbox.stop();
      expect(adapter.stop).toHaveBeenCalled();
    });

    it('does not throw if adapter has no stop', async () => {
      const adapter = createMockAdapter();
      delete adapter.stop;
      const sandbox = createSecuredSandbox(adapter, 'sid-123', 'full');
      await expect(sandbox.stop()).resolves.not.toThrow();
    });
  });

  describe('properties', () => {
    it('exposes sessionId', () => {
      const sandbox = createSecuredSandbox(
        createMockAdapter(),
        'sid-123',
        'full',
      );
      expect(sandbox.sessionId).toBe('sid-123');
    });

    it('exposes securityMode', () => {
      const sandbox = createSecuredSandbox(
        createMockAdapter(),
        'sid-123',
        'landlock',
      );
      expect(sandbox.securityMode).toBe('landlock');
    });
  });
});
