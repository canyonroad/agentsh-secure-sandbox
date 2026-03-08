import { describe, it, expect } from 'vitest';
import yaml from 'js-yaml';
import { serializePolicy, systemPolicyYaml } from './serialize.js';

describe('serializePolicy', () => {
  it('serializes file deny rule', () => {
    const result = serializePolicy({ file: [{ deny: ['**/.env', '~/.ssh/**'] }] });
    const parsed = yaml.load(result) as any;
    expect(parsed.file_rules).toHaveLength(1);
    expect(parsed.file_rules[0].name).toBe('file-rule-0');
    expect(parsed.file_rules[0].paths).toEqual(['**/.env', '~/.ssh/**']);
    expect(parsed.file_rules[0].decision).toBe('deny');
  });

  it('serializes file allow rule with ops', () => {
    const result = serializePolicy({ file: [{ allow: '/workspace/**', ops: ['read', 'write'] }] });
    const parsed = yaml.load(result) as any;
    expect(parsed.file_rules[0].decision).toBe('allow');
    expect(parsed.file_rules[0].operations).toEqual(['read', 'write']);
    expect(parsed.file_rules[0].paths).toEqual(['/workspace/**']);
  });

  it('normalizes single string to array for paths', () => {
    const result = serializePolicy({ file: [{ deny: '**/.env' }] });
    const parsed = yaml.load(result) as any;
    expect(parsed.file_rules[0].paths).toEqual(['**/.env']);
  });

  it('serializes file redirect rule', () => {
    const result = serializePolicy({ file: [{ redirect: '/secret', to: '/dev/null' }] });
    const parsed = yaml.load(result) as any;
    expect(parsed.file_rules[0].decision).toBe('redirect');
    expect(parsed.file_rules[0].redirect_to).toBe('/dev/null');
  });

  it('serializes file audit rule', () => {
    const result = serializePolicy({ file: [{ audit: '/workspace/**', ops: ['write'] }] });
    const parsed = yaml.load(result) as any;
    expect(parsed.file_rules[0].decision).toBe('audit');
  });

  it('serializes file softDelete rule', () => {
    const result = serializePolicy({ file: [{ softDelete: '/tmp/**' }] });
    const parsed = yaml.load(result) as any;
    expect(parsed.file_rules[0].decision).toBe('soft_delete');
  });

  it('serializes file deny rule with ops', () => {
    const result = serializePolicy({
      file: [{ deny: '**/.cursorrules', ops: ['write', 'create'] }],
    });
    const parsed = yaml.load(result) as any;
    expect(parsed.file_rules[0].decision).toBe('deny');
    expect(parsed.file_rules[0].operations).toEqual(['write', 'create']);
  });

  it('serializes command redirect with object target', () => {
    const result = serializePolicy({
      commands: [{ redirect: ['curl', 'wget'], to: { cmd: 'agentsh-fetch', args: ['--audit'] } }],
    });
    const parsed = yaml.load(result) as any;
    expect(parsed.command_rules[0].decision).toBe('redirect');
    expect(parsed.command_rules[0].redirect_to.command).toBe('agentsh-fetch');
    expect(parsed.command_rules[0].redirect_to.args).toEqual(['--audit']);
  });

  it('serializes command redirect with string target', () => {
    const result = serializePolicy({
      commands: [{ redirect: 'curl', to: '/usr/local/bin/safe-curl' }],
    });
    const parsed = yaml.load(result) as any;
    expect(parsed.command_rules[0].redirect_to).toBe('/usr/local/bin/safe-curl');
  });

  it('serializes network rules', () => {
    const result = serializePolicy({
      network: [
        { allow: ['registry.npmjs.org'], ports: [443] },
        { deny: '*' },
      ],
    });
    const parsed = yaml.load(result) as any;
    expect(parsed.network_rules).toHaveLength(2);
    expect(parsed.network_rules[0].decision).toBe('allow');
    expect(parsed.network_rules[0].ports).toEqual([443]);
    expect(parsed.network_rules[1].decision).toBe('deny');
  });

  it('serializes env rules', () => {
    const result = serializePolicy({
      env: [{ commands: ['node'], allow: ['PATH'], deny: ['SECRET'] }],
    });
    const parsed = yaml.load(result) as any;
    expect(parsed.env_rules).toHaveLength(1);
    expect(parsed.env_rules[0].commands).toEqual(['node']);
    expect(parsed.env_rules[0].allow).toEqual(['PATH']);
    expect(parsed.env_rules[0].deny).toEqual(['SECRET']);
  });

  it('serializes dns redirects', () => {
    const result = serializePolicy({
      dns: [{ match: '.*\\.example\\.com', resolveTo: '127.0.0.1' }],
    });
    const parsed = yaml.load(result) as any;
    expect(parsed.dns_redirects).toHaveLength(1);
    expect(parsed.dns_redirects[0].resolve_to).toBe('127.0.0.1');
  });

  it('serializes connect redirects', () => {
    const result = serializePolicy({
      connect: [{ match: 'api.prod.com:443', redirectTo: 'localhost:8080' }],
    });
    const parsed = yaml.load(result) as any;
    expect(parsed.connect_redirects).toHaveLength(1);
    expect(parsed.connect_redirects[0].redirect_to).toBe('localhost:8080');
  });

  it('omits empty categories', () => {
    const result = serializePolicy({ file: [{ allow: '/workspace/**' }] });
    const parsed = yaml.load(result) as any;
    expect(parsed.network_rules).toBeUndefined();
    expect(parsed.command_rules).toBeUndefined();
  });

  it('handles full agentDefault policy', async () => {
    const { agentDefault } = await import('./presets.js');
    const result = serializePolicy(agentDefault());
    const parsed = yaml.load(result) as any;
    expect(parsed.file_rules.length).toBeGreaterThan(0);
    expect(parsed.network_rules.length).toBeGreaterThan(0);
    expect(parsed.command_rules.length).toBeGreaterThan(0);
  });
});

describe('systemPolicyYaml', () => {
  it('returns valid YAML', () => {
    const result = systemPolicyYaml();
    const parsed = yaml.load(result) as any;
    expect(parsed).toBeDefined();
  });

  it('contains self-protection file rules', () => {
    const parsed = yaml.load(systemPolicyYaml()) as any;
    const names = parsed.file_rules.map((r: any) => r.name);
    expect(names).toContain('_system-protect-config');
    expect(names).toContain('_system-protect-binary');
    expect(names).toContain('_system-protect-shim-files');
  });

  it('contains process protection command rule', () => {
    const parsed = yaml.load(systemPolicyYaml()) as any;
    const names = parsed.command_rules.map((r: any) => r.name);
    expect(names).toContain('_system-protect-process');
  });

  it('all self-protection rules are deny', () => {
    const parsed = yaml.load(systemPolicyYaml()) as any;
    for (const rule of parsed.file_rules) {
      expect(rule.decision).toBe('deny');
    }
    for (const rule of parsed.command_rules) {
      expect(rule.decision).toBe('deny');
    }
  });
});
