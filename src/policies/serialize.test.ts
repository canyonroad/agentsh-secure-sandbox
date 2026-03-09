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

  // ─── Package rules ──────────────────────────────────────────

  it('serializes a basic package rule with match and action', () => {
    const result = serializePolicy({
      packageRules: [
        { match: { findingType: 'malware' }, action: 'block' },
      ],
    });
    const parsed = yaml.load(result) as any;
    expect(parsed.package_rules).toHaveLength(1);
    expect(parsed.package_rules[0].match.finding_type).toBe('malware');
    expect(parsed.package_rules[0].action).toBe('block');
  });

  it('maps camelCase PackageMatch fields to snake_case', () => {
    const result = serializePolicy({
      packageRules: [
        {
          match: {
            namePatterns: ['lodash.*'],
            findingType: 'vulnerability',
            licenseSpdx: { allow: ['MIT', 'Apache-2.0'] },
          },
          action: 'warn',
        },
      ],
    });
    const parsed = yaml.load(result) as any;
    const match = parsed.package_rules[0].match;
    expect(match.name_patterns).toEqual(['lodash.*']);
    expect(match.finding_type).toBe('vulnerability');
    expect(match.license_spdx).toEqual({ allow: ['MIT', 'Apache-2.0'] });
    // Ensure camelCase keys are NOT in YAML output
    expect(match.namePatterns).toBeUndefined();
    expect(match.findingType).toBeUndefined();
    expect(match.licenseSpdx).toBeUndefined();
  });

  it('serializes package rule with optional reason', () => {
    const result = serializePolicy({
      packageRules: [
        {
          match: { findingType: 'malware' },
          action: 'block',
          reason: 'Malware is never acceptable',
        },
      ],
    });
    const parsed = yaml.load(result) as any;
    expect(parsed.package_rules[0].reason).toBe('Malware is never acceptable');
  });

  it('omits reason when not provided', () => {
    const result = serializePolicy({
      packageRules: [
        { match: { findingType: 'malware' }, action: 'block' },
      ],
    });
    const parsed = yaml.load(result) as any;
    expect(parsed.package_rules[0].reason).toBeUndefined();
  });

  it('serializes severity as a single string', () => {
    const result = serializePolicy({
      packageRules: [
        { match: { severity: 'critical' }, action: 'block' },
      ],
    });
    const parsed = yaml.load(result) as any;
    expect(parsed.package_rules[0].match.severity).toBe('critical');
  });

  it('serializes severity as a string array', () => {
    const result = serializePolicy({
      packageRules: [
        { match: { severity: ['critical', 'high'] }, action: 'block' },
      ],
    });
    const parsed = yaml.load(result) as any;
    expect(parsed.package_rules[0].match.severity).toEqual(['critical', 'high']);
  });

  it('serializes licenseSpdx with deny list', () => {
    const result = serializePolicy({
      packageRules: [
        {
          match: { licenseSpdx: { deny: ['GPL-3.0', 'AGPL-3.0'] } },
          action: 'block',
        },
      ],
    });
    const parsed = yaml.load(result) as any;
    expect(parsed.package_rules[0].match.license_spdx).toEqual({
      deny: ['GPL-3.0', 'AGPL-3.0'],
    });
  });

  it('serializes package rule with packages list', () => {
    const result = serializePolicy({
      packageRules: [
        {
          match: { packages: ['event-stream', 'ua-parser-js'] },
          action: 'block',
          reason: 'Known compromised packages',
        },
      ],
    });
    const parsed = yaml.load(result) as any;
    expect(parsed.package_rules[0].match.packages).toEqual([
      'event-stream',
      'ua-parser-js',
    ]);
  });

  it('serializes package rule with ecosystem and options', () => {
    const result = serializePolicy({
      packageRules: [
        {
          match: {
            ecosystem: 'npm',
            options: { maxAge: 30, requireLicense: true },
          },
          action: 'warn',
        },
      ],
    });
    const parsed = yaml.load(result) as any;
    const match = parsed.package_rules[0].match;
    expect(match.ecosystem).toBe('npm');
    expect(match.options).toEqual({ maxAge: 30, requireLicense: true });
  });

  it('serializes package rule with reasons', () => {
    const result = serializePolicy({
      packageRules: [
        {
          match: { reasons: ['abandoned', 'typosquat'] },
          action: 'block',
        },
      ],
    });
    const parsed = yaml.load(result) as any;
    expect(parsed.package_rules[0].match.reasons).toEqual([
      'abandoned',
      'typosquat',
    ]);
  });

  it('serializes multiple package rules', () => {
    const result = serializePolicy({
      packageRules: [
        { match: { findingType: 'malware' }, action: 'block' },
        { match: { severity: 'critical' }, action: 'block' },
        { match: { severity: 'low' }, action: 'allow' },
      ],
    });
    const parsed = yaml.load(result) as any;
    expect(parsed.package_rules).toHaveLength(3);
    expect(parsed.package_rules[0].action).toBe('block');
    expect(parsed.package_rules[1].action).toBe('block');
    expect(parsed.package_rules[2].action).toBe('allow');
  });

  it('omits package_rules when packageRules is empty', () => {
    const result = serializePolicy({ packageRules: [] });
    const parsed = yaml.load(result) as any;
    expect(parsed.package_rules).toBeUndefined();
  });

  it('omits package_rules when packageRules is not set', () => {
    const result = serializePolicy({ file: [{ allow: '/workspace/**' }] });
    const parsed = yaml.load(result) as any;
    expect(parsed.package_rules).toBeUndefined();
  });

  it('only includes provided match fields (no undefined keys)', () => {
    const result = serializePolicy({
      packageRules: [
        { match: { findingType: 'malware' }, action: 'block' },
      ],
    });
    const parsed = yaml.load(result) as any;
    const matchKeys = Object.keys(parsed.package_rules[0].match);
    expect(matchKeys).toEqual(['finding_type']);
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
