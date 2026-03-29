import { describe, it, expect, vi } from 'vitest';
import { vercel } from './vercel.js';
import { e2b } from './e2b.js';
import { daytona } from './daytona.js';
import { cloudflare } from './cloudflare.js';
import { blaxel } from './blaxel.js';
import { sprites } from './sprites.js';
import { modal } from './modal.js';
import { vercelDefaults } from './vercel.js';
import { e2bDefaults } from './e2b.js';
import { daytonaDefaults } from './daytona.js';
import { cloudflareDefaults } from './cloudflare.js';
import { blaxelDefaults } from './blaxel.js';
import { modalDefaults } from './modal.js';
import { spritesDefaults } from './sprites.js';
import { PolicyDefinitionSchema } from '../policies/schema.js';
import { serializePolicy } from '../policies/serialize.js';

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

describe('modal adapter', () => {
  it('maps exec to sandbox.exec with sh -c', async () => {
    const proc = {
      wait: vi.fn(async () => {}),
      stdout: { read: vi.fn(async () => 'out') },
      stderr: { read: vi.fn(async () => '') },
      returncode: 0,
    };
    const mock = {
      exec: vi.fn(async () => proc),
      terminate: vi.fn(),
    };
    const adapter = modal(mock);
    const result = await adapter.exec('echo', ['hello world']);
    expect(mock.exec).toHaveBeenCalledWith('sh', '-c', expect.stringContaining('echo'));
    expect(result.stdout).toBe('out');
    expect(result.exitCode).toBe(0);
  });

  it('drops sudo flag (Modal runs as root)', async () => {
    const proc = {
      wait: vi.fn(async () => {}),
      stdout: { read: vi.fn(async () => '') },
      stderr: { read: vi.fn(async () => '') },
      returncode: 0,
    };
    const mock = { exec: vi.fn(async () => proc), terminate: vi.fn() };
    const adapter = modal(mock);
    await adapter.exec('chmod', ['755', '/tmp/x'], { sudo: true });
    expect(mock.exec).toHaveBeenCalledWith(
      'sh', '-c', expect.stringMatching(/^chmod /),
    );
  });

  it('detached returns immediately with exitCode 0', async () => {
    const proc = {
      wait: vi.fn(async () => {}),
      stdout: { read: vi.fn(async () => '') },
      stderr: { read: vi.fn(async () => '') },
      returncode: 0,
    };
    const mock = { exec: vi.fn(async () => proc), terminate: vi.fn() };
    const adapter = modal(mock);
    const result = await adapter.exec('server', ['start'], { detached: true });
    expect(result.exitCode).toBe(0);
  });

  it('includes env vars in command', async () => {
    const proc = {
      wait: vi.fn(async () => {}),
      stdout: { read: vi.fn(async () => '') },
      stderr: { read: vi.fn(async () => '') },
      returncode: 0,
    };
    const mock = { exec: vi.fn(async () => proc), terminate: vi.fn() };
    const adapter = modal(mock);
    await adapter.exec('agentsh', ['exec'], { env: { TRACEPARENT: '00-abc-def-01' } });
    expect(mock.exec).toHaveBeenCalledWith(
      'sh', '-c', expect.stringContaining('TRACEPARENT=00-abc-def-01'),
    );
  });

  it('writeFile uses base64 approach', async () => {
    const proc = {
      wait: vi.fn(async () => {}),
      stdout: { read: vi.fn(async () => '') },
      stderr: { read: vi.fn(async () => '') },
      returncode: 0,
    };
    const mock = { exec: vi.fn(async () => proc), terminate: vi.fn() };
    const adapter = modal(mock);
    await adapter.writeFile('/workspace/test.txt', 'hello');
    expect(mock.exec).toHaveBeenCalledWith('sh', '-c', expect.stringContaining('base64'));
  });

  it('readFile uses cat', async () => {
    const proc = {
      wait: vi.fn(async () => {}),
      stdout: { read: vi.fn(async () => 'file content') },
      stderr: { read: vi.fn(async () => '') },
      returncode: 0,
    };
    const mock = { exec: vi.fn(async () => proc), terminate: vi.fn() };
    const adapter = modal(mock);
    const content = await adapter.readFile('/workspace/test.txt');
    expect(mock.exec).toHaveBeenCalledWith('sh', '-c', expect.stringContaining('cat'));
    expect(content).toBe('file content');
  });

  it('writeFile throws on non-zero exit', async () => {
    const proc = {
      wait: vi.fn(async () => {}),
      stdout: { read: vi.fn(async () => '') },
      stderr: { read: vi.fn(async () => 'permission denied') },
      returncode: 1,
    };
    const mock = { exec: vi.fn(async () => proc), terminate: vi.fn() };
    const adapter = modal(mock);
    await expect(adapter.writeFile('/etc/test', 'data')).rejects.toThrow('writeFile failed');
  });

  it('readFile throws on non-zero exit', async () => {
    const proc = {
      wait: vi.fn(async () => {}),
      stdout: { read: vi.fn(async () => '') },
      stderr: { read: vi.fn(async () => 'no such file') },
      returncode: 1,
    };
    const mock = { exec: vi.fn(async () => proc), terminate: vi.fn() };
    const adapter = modal(mock);
    await expect(adapter.readFile('/missing')).rejects.toThrow('readFile failed');
  });

  it('exec returns error info when sandbox.exec throws', async () => {
    const mock = {
      exec: vi.fn(async () => { throw { stdout: '', stderr: 'command not found', returncode: 127 }; }),
      terminate: vi.fn(),
    };
    const adapter = modal(mock);
    const result = await adapter.exec('nonexistent', []);
    expect(result.exitCode).toBe(127);
    expect(result.stderr).toBe('command not found');
  });

  it('stop calls sandbox.terminate', async () => {
    const mock = {
      exec: vi.fn(),
      terminate: vi.fn(async () => {}),
    };
    const adapter = modal(mock);
    await adapter.stop!();
    expect(mock.terminate).toHaveBeenCalled();
  });
});

// ─── Provider defaults ──────────────────────────────────────

describe('provider defaults', () => {
  const providers = [
    { name: 'vercelDefaults', fn: vercelDefaults },
    { name: 'e2bDefaults', fn: e2bDefaults },
    { name: 'daytonaDefaults', fn: daytonaDefaults },
    { name: 'cloudflareDefaults', fn: cloudflareDefaults },
    { name: 'blaxelDefaults', fn: blaxelDefaults },
    { name: 'modalDefaults', fn: modalDefaults },
    { name: 'spritesDefaults', fn: spritesDefaults },
  ];

  for (const { name, fn } of providers) {
    describe(name, () => {
      it('returns an object with policy', () => {
        const defaults = fn();
        expect(defaults).toBeDefined();
      });

      it('policy validates against PolicyDefinitionSchema', () => {
        const defaults = fn();
        if (defaults.policy) {
          const result = PolicyDefinitionSchema.safeParse(defaults.policy);
          expect(result.success).toBe(true);
        }
      });

      it('policy serializes to valid YAML', () => {
        const defaults = fn();
        if (defaults.policy) {
          const yamlStr = serializePolicy(defaults.policy as any);
          expect(yamlStr).toBeDefined();
          expect(yamlStr.length).toBeGreaterThan(0);
        }
      });
    });
  }

  it('vercelDefaults includes /vercel/sandbox paths', () => {
    const { policy } = vercelDefaults() as any;
    const allPaths = policy.file
      .filter((r: any) => 'allow' in r)
      .flatMap((r: any) => Array.isArray(r.allow) ? r.allow : [r.allow]);
    expect(allPaths).toContain('/vercel/sandbox/**');
  });

  it('e2bDefaults denies E2B internals', () => {
    const { policy } = e2bDefaults() as any;
    const denyPaths = policy.file
      .filter((r: any) => 'deny' in r)
      .flatMap((r: any) => Array.isArray(r.deny) ? r.deny : [r.deny]);
    expect(denyPaths).toContain('/usr/bin/envd');
  });

  it('e2bDefaults blocks E2B internal network', () => {
    const { policy } = e2bDefaults() as any;
    const denyCidrs = policy.network
      .filter((r: any) => 'denyCidrs' in r)
      .flatMap((r: any) => r.denyCidrs);
    expect(denyCidrs).toContain('192.0.2.0/24');
  });

  it('cloudflareDefaults includes /home/sandbox paths', () => {
    const { policy } = cloudflareDefaults() as any;
    const allPaths = policy.file
      .filter((r: any) => 'allow' in r)
      .flatMap((r: any) => Array.isArray(r.allow) ? r.allow : [r.allow]);
    expect(allPaths).toContain('/home/sandbox/**');
  });

  it('daytonaDefaults includes /home/daytona paths', () => {
    const { policy } = daytonaDefaults() as any;
    const allPaths = policy.file
      .filter((r: any) => 'allow' in r)
      .flatMap((r: any) => Array.isArray(r.allow) ? r.allow : [r.allow]);
    expect(allPaths).toContain('/home/daytona/**');
  });

  it('daytonaDefaults allows GitLab and Bitbucket', () => {
    const { policy } = daytonaDefaults() as any;
    const allowDomains = policy.network
      .filter((r: any) => 'allow' in r)
      .flatMap((r: any) => Array.isArray(r.allow) ? r.allow : [r.allow]);
    expect(allowDomains).toContain('gitlab.com');
    expect(allowDomains).toContain('bitbucket.org');
  });

  it('blaxelDefaults includes /app workspace', () => {
    const { policy } = blaxelDefaults() as any;
    const allPaths = policy.file
      .filter((r: any) => 'allow' in r)
      .flatMap((r: any) => Array.isArray(r.allow) ? r.allow : [r.allow]);
    expect(allPaths).toContain('/app/**');
  });
});
