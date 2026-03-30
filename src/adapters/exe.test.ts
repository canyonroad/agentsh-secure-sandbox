import { describe, it, expect, vi, beforeEach } from 'vitest';
import { exeDefaults } from './exe.js';
import { PolicyDefinitionSchema } from '../policies/schema.js';
import { serializePolicy } from '../policies/serialize.js';

// Mock child_process — scoped to this file so it doesn't affect other adapter tests
const mockExecFile = vi.hoisted(() => vi.fn());
vi.mock('node:child_process', () => ({ execFile: mockExecFile }));

describe('exe adapter', () => {
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
