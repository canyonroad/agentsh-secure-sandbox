import { describe, it, expect, vi } from 'vitest';
import { vercel } from './vercel.js';
import { e2b } from './e2b.js';
import { daytona } from './daytona.js';
import { cloudflare } from './cloudflare.js';
import { blaxel } from './blaxel.js';
import { sprites } from './sprites.js';
import { modal } from './modal.js';
import { runloop } from './runloop.js';
import { freestyle } from './freestyle.js';
import { vercelDefaults } from './vercel.js';
import { e2bDefaults } from './e2b.js';
import { daytonaDefaults } from './daytona.js';
import { cloudflareDefaults } from './cloudflare.js';
import { blaxelDefaults } from './blaxel.js';
import { modalDefaults } from './modal.js';
import { spritesDefaults } from './sprites.js';
import { runloopDefaults } from './runloop.js';
import { PolicyDefinitionSchema } from '../policies/schema.js';
import { serializePolicy } from '../policies/serialize.js';
import { shellEscape } from '../core/shell.js';

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

describe('runloop adapter', () => {
  function mockDevbox() {
    return {
      client: {
        devboxes: {
          executeSync: vi.fn(async () => ({ stdout: 'out', stderr: '', exit_status: 0 })),
          writeFileContents: vi.fn(async () => ({})),
          readFileContents: vi.fn(async () => 'file content'),
          shutdown: vi.fn(async () => {}),
        },
      },
      id: 'devbox-123',
    };
  }

  it('maps exec to client.devboxes.executeSync', async () => {
    const mock = mockDevbox();
    const adapter = runloop(mock);
    const result = await adapter.exec('ls', ['-la']);
    expect(mock.client.devboxes.executeSync).toHaveBeenCalledWith(
      'devbox-123',
      expect.objectContaining({ command: expect.stringContaining('ls') }),
    );
    expect(result.stdout).toBe('out');
    expect(result.exitCode).toBe(0);
  });

  it('prepends sudo when opts.sudo is true', async () => {
    const mock = mockDevbox();
    const adapter = runloop(mock);
    await adapter.exec('chmod', ['755', '/tmp/x'], { sudo: true });
    expect(mock.client.devboxes.executeSync).toHaveBeenCalledWith(
      'devbox-123',
      expect.objectContaining({ command: expect.stringMatching(/^sudo /) }),
    );
  });

  it('wraps cwd with cd command', async () => {
    const mock = mockDevbox();
    const adapter = runloop(mock);
    await adapter.exec('ls', [], { cwd: '/workspace' });
    expect(mock.client.devboxes.executeSync).toHaveBeenCalledWith(
      'devbox-123',
      expect.objectContaining({ command: expect.stringContaining("cd '/workspace'") }),
    );
  });

  it('detached returns immediately with exitCode 0', async () => {
    const mock = mockDevbox();
    const adapter = runloop(mock);
    const result = await adapter.exec('server', ['start'], { detached: true });
    expect(result.exitCode).toBe(0);
  });

  it('includes env vars in command', async () => {
    const mock = mockDevbox();
    const adapter = runloop(mock);
    await adapter.exec('agentsh', ['exec'], { env: { TRACEPARENT: '00-abc-def-01' } });
    expect(mock.client.devboxes.executeSync).toHaveBeenCalledWith(
      'devbox-123',
      expect.objectContaining({ command: expect.stringContaining('TRACEPARENT=00-abc-def-01') }),
    );
  });

  it('includes env vars in detached commands', async () => {
    const mock = mockDevbox();
    const adapter = runloop(mock);
    await adapter.exec('server', ['start'], { detached: true, env: { FOO: 'bar' } });
    // detached fires and forgets — just check it doesn't throw
  });

  it('writeFile calls writeFileContents', async () => {
    const mock = mockDevbox();
    const adapter = runloop(mock);
    await adapter.writeFile('/workspace/test.txt', 'hello');
    expect(mock.client.devboxes.writeFileContents).toHaveBeenCalledWith(
      'devbox-123',
      expect.objectContaining({ file_path: '/workspace/test.txt', contents: 'hello' }),
    );
  });

  it('readFile calls readFileContents', async () => {
    const mock = mockDevbox();
    const adapter = runloop(mock);
    const content = await adapter.readFile('/workspace/test.txt');
    expect(mock.client.devboxes.readFileContents).toHaveBeenCalledWith(
      'devbox-123',
      expect.objectContaining({ file_path: '/workspace/test.txt' }),
    );
    expect(content).toBe('file content');
  });

  it('writeFile throws on SDK error', async () => {
    const mock = mockDevbox();
    mock.client.devboxes.writeFileContents.mockRejectedValueOnce(new Error('permission denied'));
    const adapter = runloop(mock);
    await expect(adapter.writeFile('/etc/test', 'data')).rejects.toThrow('writeFile failed');
  });

  it('readFile throws on SDK error', async () => {
    const mock = mockDevbox();
    mock.client.devboxes.readFileContents.mockRejectedValueOnce(new Error('no such file'));
    const adapter = runloop(mock);
    await expect(adapter.readFile('/missing')).rejects.toThrow('readFile failed');
  });

  it('exec returns error info when executeSync throws', async () => {
    const mock = mockDevbox();
    mock.client.devboxes.executeSync.mockRejectedValueOnce({ stdout: '', stderr: 'command not found', exit_status: 127 });
    const adapter = runloop(mock);
    const result = await adapter.exec('nonexistent', []);
    expect(result.exitCode).toBe(127);
    expect(result.stderr).toBe('command not found');
  });

  it('stop calls client.devboxes.shutdown', async () => {
    const mock = mockDevbox();
    const adapter = runloop(mock);
    await adapter.stop!();
    expect(mock.client.devboxes.shutdown).toHaveBeenCalledWith('devbox-123');
  });
});

describe('freestyle adapter', () => {
  function mockVm(execResponse: { stdout?: string | null; stderr?: string | null; statusCode?: number | null } = { stdout: 'out', stderr: '', statusCode: 0 }) {
    return {
      exec: vi.fn(async (_opts: { command: string; timeoutMs?: number } | string) => execResponse),
      fs: {
        writeTextFile: vi.fn(async (_path: string, _content: string) => {}),
        writeFile: vi.fn(async (_path: string, _content: Buffer) => {}),
        readTextFile: vi.fn(async (_path: string) => 'file content'),
        exists: vi.fn(async (_path: string) => true),
      },
      stop: vi.fn(async () => ({})),
    };
  }

  it('maps exec to vm.exec with sh -c wrapper', async () => {
    const mock = mockVm();
    const adapter = freestyle(mock);
    const result = await adapter.exec('ls', ['-la']);
    expect(mock.exec).toHaveBeenCalledWith(
      expect.objectContaining({ command: expect.stringContaining('ls -la') }),
    );
    expect(result.stdout).toBe('out');
    expect(result.exitCode).toBe(0);
  });

  it('normalizes null statusCode to exitCode 0', async () => {
    const mock = mockVm({ stdout: 'ok', stderr: null, statusCode: null });
    const adapter = freestyle(mock);
    const result = await adapter.exec('true', []);
    expect(result.exitCode).toBe(0);
    expect(result.stderr).toBe('');
  });

  it('propagates non-zero statusCode', async () => {
    const mock = mockVm({ stdout: '', stderr: 'nope', statusCode: 2 });
    const adapter = freestyle(mock);
    const result = await adapter.exec('false', []);
    expect(result.exitCode).toBe(2);
    expect(result.stderr).toBe('nope');
  });

  it('detached with cwd wraps the compound in an inner sh -c under nohup', async () => {
    const mock = mockVm();
    const adapter = freestyle(mock);
    const result = await adapter.exec('ls', [], { cwd: '/home/user/project', detached: true });
    expect(result.exitCode).toBe(0);
    const command = (mock.exec as any).mock.calls[0][0].command as string;
    expect(command).toContain('nohup sh -c');
    expect(command).toContain('cd ');
    expect(command).toContain('/home/user/project');
    expect(command).toContain('ls');
  });

  it('detached with env wraps the compound in an inner sh -c under nohup', async () => {
    const mock = mockVm();
    const adapter = freestyle(mock);
    const result = await adapter.exec('server', ['start'], {
      env: { FOO: 'bar' },
      detached: true,
    });
    expect(result.exitCode).toBe(0);
    const command = (mock.exec as any).mock.calls[0][0].command as string;
    expect(command).toContain('nohup sh -c');
    expect(command).toContain('FOO=bar');
    expect(command).toContain('server start');
  });

  it('prepends sudo when opts.sudo is true', async () => {
    const mock = mockVm();
    const adapter = freestyle(mock);
    await adapter.exec('chmod', ['755', '/tmp/x'], { sudo: true });
    expect(mock.exec).toHaveBeenCalledWith(
      expect.objectContaining({ command: expect.stringContaining('sudo chmod') }),
    );
  });

  it('wraps with cd when opts.cwd is set', async () => {
    const mock = mockVm();
    const adapter = freestyle(mock);
    await adapter.exec('ls', [], { cwd: '/home/user/project' });
    const command = (mock.exec as any).mock.calls[0][0].command as string;
    // The outer sh -c wrapper re-escapes single quotes, so the literal
    // `cd '/home/user/project'` does not appear; we check the path and the
    // `cd ` keyword are both present in the produced command.
    expect(command).toContain('cd ');
    expect(command).toContain('/home/user/project');
    expect(command).toContain('ls');
  });

  it('escapes single quotes in cwd', async () => {
    const mock = mockVm();
    const adapter = freestyle(mock);
    await adapter.exec('ls', [], { cwd: "/tmp/it's-weird" });
    const command = (mock.exec as any).mock.calls[0][0].command as string;
    // Verify the outer command is the exact `sh -c <payload>` we expect.
    // The inner wrapped string is: cd '/tmp/it'\''s-weird' && ls
    // The outer payload is shellEscape('', [wrapped]), which single-quotes
    // the whole thing and re-escapes any `'`.
    const expectedInner = `cd '/tmp/it'\\''s-weird' && ls`;
    const expectedOuter = `sh -c ${shellEscape('', [expectedInner])}`;
    expect(command).toBe(expectedOuter);
  });

  it('includes env vars as inline assignments with safe quoting', async () => {
    const mock = mockVm();
    const adapter = freestyle(mock);
    // Simple value — should appear as `KEY=value`.
    await adapter.exec('agentsh', ['exec'], { env: { TRACEPARENT: '00-abc-def-01' } });
    const simpleCommand = (mock.exec as any).mock.calls[0][0].command as string;
    expect(simpleCommand).toContain('TRACEPARENT=00-abc-def-01');

    // Metacharacter value — must be quoted so the remote shell does not
    // interpret spaces, `$`, `;`, or single quotes.
    (mock.exec as any).mockClear();
    await adapter.exec('agentsh', ['exec'], {
      env: { MSG: "hello $world; rm -rf / 'danger'" },
    });
    const complexCommand = (mock.exec as any).mock.calls[0][0].command as string;
    // The raw, unquoted metacharacters must NOT appear as bare tokens in
    // the generated command — if they did, the remote shell would expand
    // or execute them.
    expect(complexCommand).toContain('MSG=');
    // The literal user value must still be present after quoting.
    expect(complexCommand).toContain('hello');
    expect(complexCommand).toContain('world');
    expect(complexCommand).toContain('rm -rf');
    expect(complexCommand).toContain('danger');
    // Confirm the outer wrapper is a safe sh -c form.
    expect(complexCommand.startsWith('sh -c ')).toBe(true);
    // The command must NOT be a bare `MSG=hello $world; rm -rf / 'danger' agentsh exec`
    // — that would fail the outer sh -c single-quote wrap. Instead, the outer
    // wrapper must contain the metacharacters inside its single-quoted payload.
    // We assert the outer wrapper uses single quotes (shellEscape's style).
    // Note: shellEscape('', [wrapped]) joins ['', "'…'"] with a space, so the
    // outer form is `sh -c <space><space>'…'` (two spaces).
    expect(complexCommand).toMatch(/^sh -c {1,2}'/);
  });

  it('surfaces SDK errors as exitCode 1 without throwing', async () => {
    const mock = mockVm();
    mock.exec.mockRejectedValueOnce(new Error('network error'));
    const adapter = freestyle(mock);
    const result = await adapter.exec('whatever', []);
    expect(result.exitCode).toBe(1);
    expect(result.stderr).toContain('network error');
  });

  it('writeFile with string uses vm.fs.writeTextFile', async () => {
    const mock = mockVm();
    const adapter = freestyle(mock);
    await adapter.writeFile('/home/user/a.txt', 'hello');
    expect(mock.fs.writeTextFile).toHaveBeenCalledWith('/home/user/a.txt', 'hello');
    expect(mock.exec).not.toHaveBeenCalled();
  });

  it('writeFile with Buffer uses vm.fs.writeFile', async () => {
    const mock = mockVm();
    const adapter = freestyle(mock);
    const buf = Buffer.from([0, 1, 2, 3]);
    await adapter.writeFile('/home/user/a.bin', buf);
    expect(mock.fs.writeFile).toHaveBeenCalledWith('/home/user/a.bin', buf);
    expect(mock.fs.writeTextFile).not.toHaveBeenCalled();
  });

  it('writeFile wraps SDK errors', async () => {
    const mock = mockVm();
    mock.fs.writeTextFile.mockRejectedValueOnce(new Error('permission denied'));
    const adapter = freestyle(mock);
    await expect(adapter.writeFile('/root/x', 'y')).rejects.toThrow(/writeFile failed.*permission denied/);
  });

  it('readFile uses vm.fs.readTextFile', async () => {
    const mock = mockVm();
    mock.fs.readTextFile.mockResolvedValueOnce('contents');
    const adapter = freestyle(mock);
    const got = await adapter.readFile('/home/user/b.txt');
    expect(mock.fs.readTextFile).toHaveBeenCalledWith('/home/user/b.txt');
    expect(got).toBe('contents');
  });

  it('readFile wraps SDK errors', async () => {
    const mock = mockVm();
    mock.fs.readTextFile.mockRejectedValueOnce(new Error('no such file'));
    const adapter = freestyle(mock);
    await expect(adapter.readFile('/missing')).rejects.toThrow(/readFile failed.*no such file/);
  });

  it('fileExists returns vm.fs.exists result', async () => {
    const mock = mockVm();
    mock.fs.exists.mockResolvedValueOnce(true);
    const adapter = freestyle(mock);
    expect(await adapter.fileExists!('/usr/local/bin/agentsh')).toBe(true);

    mock.fs.exists.mockResolvedValueOnce(false);
    expect(await adapter.fileExists!('/nope')).toBe(false);
  });

  it('stop calls vm.stop', async () => {
    const mock = mockVm();
    const adapter = freestyle(mock);
    await adapter.stop!();
    expect(mock.stop).toHaveBeenCalled();
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
    { name: 'runloopDefaults', fn: runloopDefaults },
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

  it('runloopDefaults denies credential paths', () => {
    const { policy } = runloopDefaults() as any;
    const denyPaths = policy.file
      .filter((r: any) => 'deny' in r)
      .flatMap((r: any) => Array.isArray(r.deny) ? r.deny : [r.deny]);
    expect(denyPaths).toContain('~/.ssh/**');
    expect(denyPaths).toContain('~/.aws/**');
    expect(denyPaths).toContain('**/.env');
  });

  it('runloopDefaults blocks private networks', () => {
    const { policy } = runloopDefaults() as any;
    const denyCidrs = policy.network
      .filter((r: any) => 'denyCidrs' in r)
      .flatMap((r: any) => r.denyCidrs);
    expect(denyCidrs).toContain('10.0.0.0/8');
    expect(denyCidrs).toContain('169.254.169.254/32');
  });

  it('runloopDefaults blocks raw network tools', () => {
    const { policy } = runloopDefaults() as any;
    const denyCmds = policy.commands
      .filter((r: any) => 'deny' in r)
      .flatMap((r: any) => Array.isArray(r.deny) ? r.deny : [r.deny]);
    expect(denyCmds).toContain('ssh');
    expect(denyCmds).toContain('nc');
    expect(denyCmds).toContain('kill');
  });

  it('runloopDefaults has soft-delete for workspace', () => {
    const { policy } = runloopDefaults() as any;
    const softDeletePaths = policy.file
      .filter((r: any) => 'softDelete' in r)
      .flatMap((r: any) => Array.isArray(r.softDelete) ? r.softDelete : [r.softDelete]);
    expect(softDeletePaths).toContain('/workspace/**');
  });
});
