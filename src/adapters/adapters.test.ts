import { describe, it, expect, vi } from 'vitest';
import { vercel } from './vercel.js';
import { e2b } from './e2b.js';
import { daytona } from './daytona.js';

describe('vercel adapter', () => {
  it('maps exec to sandbox.runCommand', async () => {
    const mock = {
      runCommand: vi.fn(async () => ({ stdout: () => 'out', stderr: () => '', exitCode: 0 })),
      writeFiles: vi.fn(), readFile: vi.fn(), stop: vi.fn(),
    };
    const adapter = vercel(mock);
    const result = await adapter.exec('ls', ['-la'], { cwd: '/workspace' });
    expect(mock.runCommand).toHaveBeenCalledWith(expect.objectContaining({ cmd: 'ls', args: ['-la'], cwd: '/workspace' }));
    expect(result.stdout).toBe('out');
  });

  it('maps writeFile to sandbox.writeFiles', async () => {
    const mock = { runCommand: vi.fn(), writeFiles: vi.fn(async () => {}), readFile: vi.fn(), stop: vi.fn() };
    const adapter = vercel(mock);
    await adapter.writeFile('/workspace/test.txt', 'hello');
    expect(mock.writeFiles).toHaveBeenCalledWith([{ path: '/workspace/test.txt', content: 'hello' }]);
  });

  it('maps readFile to sandbox.readFile', async () => {
    const mock = { runCommand: vi.fn(), writeFiles: vi.fn(), readFile: vi.fn(async () => 'content'), stop: vi.fn() };
    const adapter = vercel(mock);
    expect(await adapter.readFile('/test')).toBe('content');
  });

  it('maps stop to sandbox.stop', async () => {
    const mock = { runCommand: vi.fn(), writeFiles: vi.fn(), readFile: vi.fn(), stop: vi.fn(async () => {}) };
    const adapter = vercel(mock);
    await adapter.stop!();
    expect(mock.stop).toHaveBeenCalled();
  });

  it('fileExists returns true when test -f succeeds', async () => {
    const mock = { runCommand: vi.fn(async () => ({ exitCode: 0 })), writeFiles: vi.fn(), readFile: vi.fn(), stop: vi.fn() };
    const adapter = vercel(mock);
    expect(await adapter.fileExists!('/usr/bin/agentsh')).toBe(true);
  });
});

describe('e2b adapter', () => {
  it('maps exec with shell escaping', async () => {
    const mock = {
      commands: { run: vi.fn(async () => ({ stdout: 'out', stderr: '', exitCode: 0 })) },
      files: { write: vi.fn(), read: vi.fn(), list: vi.fn() },
      kill: vi.fn(),
    };
    const adapter = e2b(mock);
    const result = await adapter.exec('echo', ['hello world']);
    expect(mock.commands.run).toHaveBeenCalledWith(
      expect.stringContaining('echo'),
      expect.objectContaining({ user: 'user' }),
    );
    expect(result.stdout).toBe('out');
  });

  it('uses root user when sudo', async () => {
    const mock = {
      commands: { run: vi.fn(async () => ({ stdout: '', stderr: '', exitCode: 0 })) },
      files: { write: vi.fn(), read: vi.fn() },
      kill: vi.fn(),
    };
    const adapter = e2b(mock);
    await adapter.exec('chmod', ['755', '/tmp/x'], { sudo: true });
    expect(mock.commands.run).toHaveBeenCalledWith(expect.any(String), expect.objectContaining({ user: 'root' }));
  });
});

describe('daytona adapter', () => {
  it('maps exec to sandbox.process.executeCommand', async () => {
    const mock = {
      process: { executeCommand: vi.fn(async () => ({ exitCode: 0, result: 'out' })) },
      fs: { uploadFile: vi.fn(), downloadFile: vi.fn() },
    };
    const adapter = daytona(mock);
    const result = await adapter.exec('ls', ['-la']);
    expect(mock.process.executeCommand).toHaveBeenCalled();
    expect(result.stdout).toBe('out');
  });

  it('maps writeFile to sandbox.fs.uploadFile', async () => {
    const mock = {
      process: { executeCommand: vi.fn() },
      fs: { uploadFile: vi.fn(async () => {}), downloadFile: vi.fn() },
    };
    const adapter = daytona(mock);
    await adapter.writeFile('/workspace/test.txt', 'hello');
    expect(mock.fs.uploadFile).toHaveBeenCalled();
  });
});
