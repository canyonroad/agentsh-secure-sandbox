import { describe, it, expect, vi } from 'vitest';
import { vercel } from './vercel.js';
import { e2b } from './e2b.js';
import { daytona } from './daytona.js';
import { cloudflare } from './cloudflare.js';
import { blaxel } from './blaxel.js';
import { sprites } from './sprites.js';

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

  it('passes env vars in structured params', async () => {
    const mock = {
      runCommand: vi.fn(async () => ({ stdout: () => '', stderr: () => '', exitCode: 0 })),
      writeFiles: vi.fn(), readFile: vi.fn(), stop: vi.fn(),
    };
    const adapter = vercel(mock);
    await adapter.exec('agentsh', ['exec'], { env: { TRACEPARENT: '00-abc-def-01' } });
    expect(mock.runCommand).toHaveBeenCalledWith(
      expect.objectContaining({ env: { TRACEPARENT: '00-abc-def-01' } }),
    );
  });

  it('maps writeFile to sandbox.writeFiles', async () => {
    const mock = { runCommand: vi.fn(), writeFiles: vi.fn(async () => {}), readFile: vi.fn(), stop: vi.fn() };
    const adapter = vercel(mock);
    await adapter.writeFile('/workspace/test.txt', 'hello');
    expect(mock.writeFiles).toHaveBeenCalledWith([{ path: '/workspace/test.txt', content: Buffer.from('hello') }]);
  });

  it('maps readFile to sandbox.readFile', async () => {
    // Vercel readFile returns a ReadableStream
    const { Readable } = await import('node:stream');
    const stream = Readable.from([Buffer.from('content')]);
    const mock = { runCommand: vi.fn(), writeFiles: vi.fn(), readFile: vi.fn(async () => stream), stop: vi.fn() };
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

  it('includes env vars as inline prefix in command', async () => {
    const mock = {
      commands: { run: vi.fn(async () => ({ stdout: '', stderr: '', exitCode: 0 })) },
      files: { write: vi.fn(), read: vi.fn() },
      kill: vi.fn(),
    };
    const adapter = e2b(mock);
    await adapter.exec('agentsh', ['exec'], { env: { TRACEPARENT: '00-abc-def-01' } });
    expect(mock.commands.run).toHaveBeenCalledWith(
      expect.stringContaining('TRACEPARENT=00-abc-def-01'),
      expect.anything(),
    );
  });

  it('includes env vars in detached commands', async () => {
    const mock = {
      commands: { run: vi.fn(async () => ({ stdout: '', stderr: '', exitCode: 0 })) },
      files: { write: vi.fn(), read: vi.fn() },
      kill: vi.fn(),
    };
    const adapter = e2b(mock);
    await adapter.exec('server', ['start'], { detached: true, env: { FOO: 'bar' } });
    expect(mock.commands.run).toHaveBeenCalledWith(
      expect.stringContaining('FOO=bar'),
      expect.anything(),
    );
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

  it('includes env vars in command', async () => {
    const mock = {
      process: { executeCommand: vi.fn(async () => ({ exitCode: 0, result: '' })) },
      fs: { uploadFile: vi.fn(), downloadFile: vi.fn() },
    };
    const adapter = daytona(mock);
    await adapter.exec('agentsh', ['exec'], { env: { TRACEPARENT: '00-abc-def-01' } });
    expect(mock.process.executeCommand).toHaveBeenCalledWith(
      expect.stringContaining('TRACEPARENT=00-abc-def-01'),
      undefined,
    );
  });

  it('includes env vars in detached commands', async () => {
    const mock = {
      process: { executeCommand: vi.fn(async () => ({ exitCode: 0 })) },
      fs: { uploadFile: vi.fn(), downloadFile: vi.fn() },
    };
    const adapter = daytona(mock);
    await adapter.exec('server', ['start'], { detached: true, env: { FOO: 'bar' } });
    expect(mock.process.executeCommand).toHaveBeenCalledWith(
      expect.stringContaining('FOO=bar'),
      undefined,
    );
  });
});

describe('cloudflare adapter', () => {
  it('maps exec to sandbox.exec with shell-escaped command', async () => {
    const mock = {
      exec: vi.fn(async () => ({ stdout: 'out', stderr: '', exitCode: 0 })),
    };
    const adapter = cloudflare(mock);
    const result = await adapter.exec('echo', ['hello world']);
    expect(mock.exec).toHaveBeenCalledWith(
      expect.stringContaining('echo'),
      expect.objectContaining({}),
    );
    expect(result.stdout).toBe('out');
  });

  it('drops sudo flag (container runs as root)', async () => {
    const mock = {
      exec: vi.fn(async () => ({ stdout: '', stderr: '', exitCode: 0 })),
    };
    const adapter = cloudflare(mock);
    await adapter.exec('chmod', ['755', '/tmp/x'], { sudo: true });
    expect(mock.exec).toHaveBeenCalledWith(
      expect.stringMatching(/^chmod /),
      expect.anything(),
    );
  });

  it('detached returns immediately with exitCode 0', async () => {
    const mock = {
      exec: vi.fn(async () => ({ stdout: '', stderr: '', exitCode: 0 })),
    };
    const adapter = cloudflare(mock);
    const result = await adapter.exec('server', ['start'], { detached: true });
    expect(result.exitCode).toBe(0);
    expect(mock.exec).toHaveBeenCalledWith(
      expect.stringContaining('nohup'),
      expect.anything(),
    );
  });

  it('includes env vars in command', async () => {
    const mock = {
      exec: vi.fn(async () => ({ stdout: '', stderr: '', exitCode: 0 })),
    };
    const adapter = cloudflare(mock);
    await adapter.exec('agentsh', ['exec'], { env: { TRACEPARENT: '00-abc-def-01' } });
    expect(mock.exec).toHaveBeenCalledWith(
      expect.stringContaining('TRACEPARENT=00-abc-def-01'),
      expect.anything(),
    );
  });

  it('includes env vars in detached commands', async () => {
    const mock = {
      exec: vi.fn(async () => ({ stdout: '', stderr: '', exitCode: 0 })),
    };
    const adapter = cloudflare(mock);
    await adapter.exec('server', ['start'], { detached: true, env: { FOO: 'bar' } });
    expect(mock.exec).toHaveBeenCalledWith(
      expect.stringContaining('FOO=bar'),
      expect.anything(),
    );
  });

  it('writeFile uses exec-based base64 approach', async () => {
    const mock = {
      exec: vi.fn(async () => ({ stdout: '', stderr: '', exitCode: 0 })),
    };
    const adapter = cloudflare(mock);
    await adapter.writeFile('/workspace/test.txt', 'hello');
    expect(mock.exec).toHaveBeenCalledWith(
      expect.stringContaining('base64'),
    );
  });

  it('readFile uses exec-based cat', async () => {
    const mock = {
      exec: vi.fn(async () => ({ stdout: 'file content', stderr: '', exitCode: 0 })),
    };
    const adapter = cloudflare(mock);
    const content = await adapter.readFile('/workspace/test.txt');
    expect(mock.exec).toHaveBeenCalledWith(expect.stringContaining('cat'));
    expect(content).toBe('file content');
  });

  it('writeFile throws on non-zero exit', async () => {
    const mock = {
      exec: vi.fn(async () => ({ stdout: '', stderr: 'permission denied', exitCode: 1 })),
    };
    const adapter = cloudflare(mock);
    await expect(adapter.writeFile('/etc/test', 'data')).rejects.toThrow('writeFile failed');
  });

  it('readFile throws on non-zero exit', async () => {
    const mock = {
      exec: vi.fn(async () => ({ stdout: '', stderr: 'no such file', exitCode: 1 })),
    };
    const adapter = cloudflare(mock);
    await expect(adapter.readFile('/missing')).rejects.toThrow('readFile failed');
  });

  it('writeFile succeeds when exitCode is undefined', async () => {
    const mock = {
      exec: vi.fn(async () => ({ stdout: '', stderr: '' })),
    };
    const adapter = cloudflare(mock);
    await expect(adapter.writeFile('/test', 'data')).resolves.toBeUndefined();
  });

  it('readFile succeeds when exitCode is undefined', async () => {
    const mock = {
      exec: vi.fn(async () => ({ stdout: 'content', stderr: '' })),
    };
    const adapter = cloudflare(mock);
    await expect(adapter.readFile('/test')).resolves.toBe('content');
  });
});

describe('blaxel adapter', () => {
  it('maps exec to sandbox.process.exec with shell-escaped command', async () => {
    const mock = {
      process: {
        exec: vi.fn(async () => ({ stdout: 'out', stderr: '', exitCode: 0 })),
      },
      fs: { write: vi.fn(), writeBinary: vi.fn(), read: vi.fn() },
      delete: vi.fn(),
    };
    const adapter = blaxel(mock);
    const result = await adapter.exec('echo', ['hello world']);
    expect(mock.process.exec).toHaveBeenCalledWith(
      expect.objectContaining({ command: expect.stringContaining('echo'), waitForCompletion: true }),
    );
    expect(result.stdout).toBe('out');
  });

  it('prepends sudo to command', async () => {
    const mock = {
      process: {
        exec: vi.fn(async () => ({ stdout: '', stderr: '', exitCode: 0 })),
      },
      fs: { write: vi.fn(), writeBinary: vi.fn(), read: vi.fn() },
      delete: vi.fn(),
    };
    const adapter = blaxel(mock);
    await adapter.exec('chmod', ['755', '/tmp/x'], { sudo: true });
    expect(mock.process.exec).toHaveBeenCalledWith(
      expect.objectContaining({ command: expect.stringMatching(/^sudo /) }),
    );
  });

  it('detached returns immediately with exitCode 0', async () => {
    const mock = {
      process: {
        exec: vi.fn(async () => ({ stdout: '', stderr: '', exitCode: 0 })),
      },
      fs: { write: vi.fn(), writeBinary: vi.fn(), read: vi.fn() },
      delete: vi.fn(),
    };
    const adapter = blaxel(mock);
    const result = await adapter.exec('server', ['start'], { detached: true });
    expect(result.exitCode).toBe(0);
    expect(mock.process.exec).toHaveBeenCalledWith(
      expect.objectContaining({ waitForCompletion: false }),
    );
  });

  it('includes env vars in command', async () => {
    const mock = {
      process: {
        exec: vi.fn(async () => ({ stdout: '', stderr: '', exitCode: 0 })),
      },
      delete: vi.fn(),
    };
    const adapter = blaxel(mock);
    await adapter.exec('agentsh', ['exec'], { env: { TRACEPARENT: '00-abc-def-01' } });
    expect(mock.process.exec).toHaveBeenCalledWith(
      expect.objectContaining({ command: expect.stringContaining('TRACEPARENT=00-abc-def-01') }),
    );
  });

  it('includes env vars in detached commands', async () => {
    const mock = {
      process: {
        exec: vi.fn(async () => ({ stdout: '', stderr: '', exitCode: 0 })),
      },
      delete: vi.fn(),
    };
    const adapter = blaxel(mock);
    await adapter.exec('server', ['start'], { detached: true, env: { FOO: 'bar' } });
    expect(mock.process.exec).toHaveBeenCalledWith(
      expect.objectContaining({ command: expect.stringContaining('FOO=bar') }),
    );
  });

  it('writeFile uses exec-based base64 approach', async () => {
    const mock = {
      process: { exec: vi.fn(async () => ({ stdout: '', stderr: '', exitCode: 0 })) },
      delete: vi.fn(),
    };
    const adapter = blaxel(mock);
    await adapter.writeFile('/workspace/test.txt', 'hello');
    expect(mock.process.exec).toHaveBeenCalledWith(
      expect.objectContaining({ command: expect.stringContaining('base64') }),
    );
  });

  it('readFile uses exec-based cat', async () => {
    const mock = {
      process: { exec: vi.fn(async () => ({ stdout: 'file content', stderr: '', exitCode: 0 })) },
      delete: vi.fn(),
    };
    const adapter = blaxel(mock);
    const content = await adapter.readFile('/workspace/test.txt');
    expect(mock.process.exec).toHaveBeenCalledWith(
      expect.objectContaining({ command: expect.stringContaining('cat') }),
    );
    expect(content).toBe('file content');
  });

  it('writeFile throws on non-zero exit', async () => {
    const mock = {
      process: { exec: vi.fn(async () => ({ stdout: '', stderr: 'permission denied', exitCode: 1 })) },
      delete: vi.fn(),
    };
    const adapter = blaxel(mock);
    await expect(adapter.writeFile('/etc/test', 'data')).rejects.toThrow('writeFile failed');
  });

  it('readFile throws on non-zero exit', async () => {
    const mock = {
      process: { exec: vi.fn(async () => ({ stdout: '', stderr: 'no such file', exitCode: 1 })) },
      delete: vi.fn(),
    };
    const adapter = blaxel(mock);
    await expect(adapter.readFile('/missing')).rejects.toThrow('readFile failed');
  });

  it('writeFile succeeds when exitCode is undefined', async () => {
    const mock = {
      process: { exec: vi.fn(async () => ({ stdout: '', stderr: '' })) },
      delete: vi.fn(),
    };
    const adapter = blaxel(mock);
    await expect(adapter.writeFile('/test', 'data')).resolves.toBeUndefined();
  });

  it('readFile succeeds when exitCode is undefined', async () => {
    const mock = {
      process: { exec: vi.fn(async () => ({ stdout: 'content', stderr: '' })) },
      delete: vi.fn(),
    };
    const adapter = blaxel(mock);
    await expect(adapter.readFile('/test')).resolves.toBe('content');
  });

  it('stop calls sandbox.delete', async () => {
    const mock = {
      process: { exec: vi.fn() },
      delete: vi.fn(async () => {}),
    };
    const adapter = blaxel(mock);
    await adapter.stop!();
    expect(mock.delete).toHaveBeenCalled();
  });
});

describe('sprites adapter', () => {
  it('maps exec to sprite.execFile with sh -c', async () => {
    const mock = {
      execFile: vi.fn(async () => ({ stdout: 'out', stderr: '' })),
      delete: vi.fn(),
    };
    const adapter = sprites(mock);
    const result = await adapter.exec('echo', ['hello world']);
    expect(mock.execFile).toHaveBeenCalledWith(
      'sh',
      ['-c', expect.stringContaining('echo')],
      expect.objectContaining({}),
    );
    expect(result.stdout).toBe('out');
    expect(result.exitCode).toBe(0);
  });

  it('prepends sudo to command', async () => {
    const mock = {
      execFile: vi.fn(async () => ({ stdout: '', stderr: '' })),
      delete: vi.fn(),
    };
    const adapter = sprites(mock);
    await adapter.exec('chmod', ['755', '/tmp/x'], { sudo: true });
    expect(mock.execFile).toHaveBeenCalledWith(
      'sh',
      ['-c', expect.stringMatching(/^sudo /)],
      expect.anything(),
    );
  });

  it('detached returns immediately with exitCode 0', async () => {
    const mock = {
      execFile: vi.fn(async () => ({ stdout: '', stderr: '' })),
      delete: vi.fn(),
    };
    const adapter = sprites(mock);
    const result = await adapter.exec('server', ['start'], { detached: true });
    expect(result.exitCode).toBe(0);
    expect(mock.execFile).toHaveBeenCalledWith(
      'sh',
      ['-c', expect.stringContaining('nohup')],
    );
  });

  it('includes env vars in command', async () => {
    const mock = {
      execFile: vi.fn(async () => ({ stdout: '', stderr: '' })),
      delete: vi.fn(),
    };
    const adapter = sprites(mock);
    await adapter.exec('agentsh', ['exec'], { env: { TRACEPARENT: '00-abc-def-01' } });
    expect(mock.execFile).toHaveBeenCalledWith(
      'sh',
      ['-c', expect.stringContaining('TRACEPARENT=00-abc-def-01')],
      expect.anything(),
    );
  });

  it('includes env vars in detached commands', async () => {
    const mock = {
      execFile: vi.fn(async () => ({ stdout: '', stderr: '' })),
      delete: vi.fn(),
    };
    const adapter = sprites(mock);
    await adapter.exec('server', ['start'], { detached: true, env: { FOO: 'bar' } });
    expect(mock.execFile).toHaveBeenCalledWith(
      'sh',
      ['-c', expect.stringContaining('FOO=bar')],
    );
  });

  it('writeFile uses sh -c with base64 pipe', async () => {
    const mock = {
      execFile: vi.fn(async () => ({ stdout: '', stderr: '' })),
      delete: vi.fn(),
    };
    const adapter = sprites(mock);
    await adapter.writeFile('/workspace/test.txt', 'hello');
    expect(mock.execFile).toHaveBeenCalledWith(
      'sh',
      ['-c', expect.stringContaining('base64')],
    );
  });

  it('readFile uses sh -c with cat', async () => {
    const mock = {
      execFile: vi.fn(async () => ({ stdout: 'file content', stderr: '' })),
      delete: vi.fn(),
    };
    const adapter = sprites(mock);
    const content = await adapter.readFile('/workspace/test.txt');
    expect(mock.execFile).toHaveBeenCalledWith(
      'sh',
      ['-c', expect.stringContaining('cat')],
    );
    expect(content).toBe('file content');
  });

  it('writeFile throws on exec error', async () => {
    const mock = {
      execFile: vi.fn(async () => { throw { exitCode: 1, stderr: 'permission denied' }; }),
      delete: vi.fn(),
    };
    const adapter = sprites(mock);
    await expect(adapter.writeFile('/etc/test', 'data')).rejects.toThrow('writeFile failed');
  });

  it('readFile throws on exec error', async () => {
    const mock = {
      execFile: vi.fn(async () => { throw { exitCode: 1, stderr: 'no such file' }; }),
      delete: vi.fn(),
    };
    const adapter = sprites(mock);
    await expect(adapter.readFile('/missing')).rejects.toThrow('readFile failed');
  });

  it('exec returns error info when sprite.execFile throws', async () => {
    const mock = {
      execFile: vi.fn(async () => { throw { stdout: '', stderr: 'command not found', exitCode: 127 }; }),
      delete: vi.fn(),
    };
    const adapter = sprites(mock);
    const result = await adapter.exec('nonexistent', []);
    expect(result.exitCode).toBe(127);
    expect(result.stderr).toBe('command not found');
  });

  it('stop calls sprite.delete', async () => {
    const mock = {
      execFile: vi.fn(),
      delete: vi.fn(async () => {}),
    };
    const adapter = sprites(mock);
    await adapter.stop!();
    expect(mock.delete).toHaveBeenCalled();
  });
});
