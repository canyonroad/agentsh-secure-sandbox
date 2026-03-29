import { describe, it, expect, vi, beforeEach } from 'vitest';
import { vercel } from './vercel.js';
import { e2b } from './e2b.js';
import { daytona } from './daytona.js';
import { cloudflare } from './cloudflare.js';
import { blaxel } from './blaxel.js';
import { sprites } from './sprites.js';
import { modal } from './modal.js';
import { runloop } from './runloop.js';
import { vercelDefaults } from './vercel.js';
import { e2bDefaults } from './e2b.js';
import { daytonaDefaults } from './daytona.js';
import { cloudflareDefaults } from './cloudflare.js';
import { blaxelDefaults } from './blaxel.js';
import { modalDefaults } from './modal.js';
import { spritesDefaults } from './sprites.js';
import { runloopDefaults } from './runloop.js';
import { exeDefaults } from './exe.js';
import { PolicyDefinitionSchema } from '../policies/schema.js';
import { serializePolicy } from '../policies/serialize.js';

// Mock child_process for the exe adapter (only exe uses it)
const mockExecFile = vi.hoisted(() => vi.fn());
vi.mock('node:child_process', () => ({ execFile: mockExecFile }));

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

describe('exe adapter', () => {
  // Import exe lazily after the mock is in place
  let exe: typeof import('./exe.js').exe;
  beforeEach(async () => {
    mockExecFile.mockReset();
    const mod = await import('./exe.js');
    exe = mod.exe;
  });

  function setupMock(stdout = '', stderr = '', exitCode = 0) {
    mockExecFile.mockImplementation(
      (_cmd: string, _args: string[], _opts: any, cb?: Function) => {
        const callback = typeof _opts === 'function' ? _opts : cb;
        if (exitCode !== 0) {
          const err: any = new Error(`exit ${exitCode}`);
          err.code = exitCode;
          err.stdout = stdout;
          err.stderr = stderr;
          process.nextTick(() => callback?.(err, stdout, stderr));
        } else {
          process.nextTick(() => callback?.(null, stdout, stderr));
        }
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

  it('single-quotes command for gateway shell', async () => {
    setupMock('');
    const adapter = exe('test-vm');
    await adapter.exec('echo', ['hello world']);
    const args = mockExecFile.mock.calls[0][1] as string[];
    const lastArg = args[args.length - 1];
    expect(lastArg).toMatch(/^ssh test-vm '.*'$/);
  });

  it('prepends sudo when opts.sudo is true', async () => {
    setupMock('');
    const adapter = exe('my-vm');
    await adapter.exec('chmod', ['755', '/tmp/x'], { sudo: true });
    const args = mockExecFile.mock.calls[0][1] as string[];
    const lastArg = args[args.length - 1];
    expect(lastArg).toContain('sudo chmod');
  });

  it('wraps cwd with cd command', async () => {
    setupMock('');
    const adapter = exe('my-vm');
    await adapter.exec('ls', [], { cwd: '/workspace' });
    const args = mockExecFile.mock.calls[0][1] as string[];
    const lastArg = args[args.length - 1];
    expect(lastArg).toContain("cd '\\''/workspace'\\''");
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
    const lastArg = args[args.length - 1];
    expect(lastArg).toContain('TRACEPARENT=');
  });

  it('writeFile uses base64 approach', async () => {
    setupMock('');
    const adapter = exe('my-vm');
    await adapter.writeFile('/workspace/test.txt', 'hello');
    const args = mockExecFile.mock.calls[0][1] as string[];
    const lastArg = args[args.length - 1];
    expect(lastArg).toContain('base64');
  });

  it('readFile uses cat', async () => {
    setupMock('file content');
    const adapter = exe('my-vm');
    const content = await adapter.readFile('/workspace/test.txt');
    const args = mockExecFile.mock.calls[0][1] as string[];
    const lastArg = args[args.length - 1];
    expect(lastArg).toContain('cat');
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
    { name: 'exeDefaults', fn: exeDefaults },
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

  it('exeDefaults blocks exe.dev internals (shelley)', () => {
    const { policy } = exeDefaults() as any;
    const denyPaths = policy.file
      .filter((r: any) => 'deny' in r)
      .flatMap((r: any) => Array.isArray(r.deny) ? r.deny : [r.deny]);
    expect(denyPaths).toContain('/usr/bin/shelley');
    expect(denyPaths).toContain('/usr/local/bin/shelley');
  });

  it('exeDefaults includes /root workspace', () => {
    const { policy } = exeDefaults() as any;
    const allPaths = policy.file
      .filter((r: any) => 'allow' in r)
      .flatMap((r: any) => Array.isArray(r.allow) ? r.allow : [r.allow]);
    expect(allPaths).toContain('/root/**');
    expect(allPaths).toContain('/workspace/**');
  });

  it('exeDefaults denies credential paths', () => {
    const { policy } = exeDefaults() as any;
    const denyPaths = policy.file
      .filter((r: any) => 'deny' in r)
      .flatMap((r: any) => Array.isArray(r.deny) ? r.deny : [r.deny]);
    expect(denyPaths).toContain('~/.ssh/**');
    expect(denyPaths).toContain('~/.aws/**');
    expect(denyPaths).toContain('**/.env');
  });

  it('exeDefaults blocks private networks', () => {
    const { policy } = exeDefaults() as any;
    const denyCidrs = policy.network
      .filter((r: any) => 'denyCidrs' in r)
      .flatMap((r: any) => r.denyCidrs);
    expect(denyCidrs).toContain('10.0.0.0/8');
    expect(denyCidrs).toContain('169.254.169.254/32');
  });

  it('exeDefaults blocks exe.dev interference commands', () => {
    const { policy } = exeDefaults() as any;
    const denyCmds = policy.commands
      .filter((r: any) => 'deny' in r)
      .flatMap((r: any) => Array.isArray(r.deny) ? r.deny : [r.deny]);
    expect(denyCmds).toContain('shelley');
    expect(denyCmds).toContain('iptables');
    expect(denyCmds).toContain('sudo');
  });

  it('exeDefaults has soft-delete for workspace', () => {
    const { policy } = exeDefaults() as any;
    const softDeletePaths = policy.file
      .filter((r: any) => 'softDelete' in r)
      .flatMap((r: any) => Array.isArray(r.softDelete) ? r.softDelete : [r.softDelete]);
    expect(softDeletePaths).toContain('/root/**');
    expect(softDeletePaths).toContain('/workspace/**');
  });

  it('exeDefaults has conservative resource limits', () => {
    const { policy } = exeDefaults() as any;
    expect(policy.resourceLimits.maxMemoryMb).toBe(2048);
    expect(policy.resourceLimits.cpuQuotaPercent).toBe(50);
    expect(policy.resourceLimits.pidsMax).toBe(100);
  });

  it('exeDefaults has env policy with blockIteration', () => {
    const { policy } = exeDefaults() as any;
    expect(policy.envPolicy.blockIteration).toBe(true);
    expect(policy.envPolicy.deny).toContain('AWS_*');
    expect(policy.envPolicy.deny).toContain('OPENAI_API_KEY');
  });

  it('exeDefaults has allowDegraded false', () => {
    const defaults = exeDefaults() as any;
    expect(defaults.serverConfig.allowDegraded).toBe(false);
  });
});
