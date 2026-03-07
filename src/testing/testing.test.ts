import { describe, it, expect } from 'vitest';
import { mockSecuredSandbox } from './index.js';

describe('mockSecuredSandbox', () => {
  it('returns a SecuredSandbox with default sessionId and securityMode', () => {
    const sandbox = mockSecuredSandbox({});
    expect(sandbox.sessionId).toBe('mock-session');
    expect(sandbox.securityMode).toBe('full');
  });

  it('exec returns matching command response', async () => {
    const sandbox = mockSecuredSandbox({
      commands: { 'ls /workspace': { stdout: 'file1.ts', stderr: '', exitCode: 0 } },
    });
    const result = await sandbox.exec('ls /workspace');
    expect(result.stdout).toBe('file1.ts');
    expect(result.exitCode).toBe(0);
  });

  it('exec returns exitCode 1 for unmatched commands', async () => {
    const sandbox = mockSecuredSandbox({ commands: {} });
    const result = await sandbox.exec('unknown');
    expect(result.exitCode).toBe(1);
  });

  it('readFile returns matching file content', async () => {
    const sandbox = mockSecuredSandbox({
      files: { '/workspace/index.ts': 'console.log("hi")' },
    });
    const result = await sandbox.readFile('/workspace/index.ts');
    expect(result.success).toBe(true);
    if (result.success) expect(result.content).toBe('console.log("hi")');
  });

  it('readFile returns failure for unknown path', async () => {
    const sandbox = mockSecuredSandbox({ files: {} });
    const result = await sandbox.readFile('/etc/shadow');
    expect(result.success).toBe(false);
  });

  it('writeFile succeeds and records for later readFile', async () => {
    const sandbox = mockSecuredSandbox({});
    const writeResult = await sandbox.writeFile('/workspace/test.txt', 'hello');
    expect(writeResult.success).toBe(true);
    const readResult = await sandbox.readFile('/workspace/test.txt');
    expect(readResult.success).toBe(true);
    if (readResult.success) expect(readResult.content).toBe('hello');
  });

  it('stop does not throw', async () => {
    const sandbox = mockSecuredSandbox({});
    await expect(sandbox.stop()).resolves.not.toThrow();
  });

  it('accepts custom securityMode and sessionId', () => {
    const sandbox = mockSecuredSandbox({}, { securityMode: 'minimal', sessionId: 'custom-123' });
    expect(sandbox.securityMode).toBe('minimal');
    expect(sandbox.sessionId).toBe('custom-123');
  });
});
