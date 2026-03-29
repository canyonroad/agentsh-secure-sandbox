import { describe, it, expect } from 'vitest';
import { PolicyDefinitionSchema, validatePolicy } from './schema.js';
import { PolicyValidationError } from '../core/errors.js';

describe('PolicyDefinitionSchema', () => {
  // File rules
  it('accepts valid file allow rule', () => {
    const result = PolicyDefinitionSchema.safeParse({
      file: [{ allow: '/workspace/**', ops: ['read', 'write'] }],
    });
    expect(result.success).toBe(true);
  });

  it('accepts file deny rule with string array', () => {
    const result = PolicyDefinitionSchema.safeParse({
      file: [{ deny: ['**/.env', '~/.ssh/**'] }],
    });
    expect(result.success).toBe(true);
  });

  it('accepts file deny rule with single string', () => {
    const result = PolicyDefinitionSchema.safeParse({
      file: [{ deny: '**/.env' }],
    });
    expect(result.success).toBe(true);
  });

  it('accepts file redirect rule', () => {
    const result = PolicyDefinitionSchema.safeParse({
      file: [{ redirect: '/secret', to: '/dev/null', ops: ['read'] }],
    });
    expect(result.success).toBe(true);
  });

  it('accepts file audit rule', () => {
    const result = PolicyDefinitionSchema.safeParse({
      file: [{ audit: '/workspace/**', ops: ['write'] }],
    });
    expect(result.success).toBe(true);
  });

  it('accepts file softDelete rule', () => {
    const result = PolicyDefinitionSchema.safeParse({
      file: [{ softDelete: '/workspace/tmp/**' }],
    });
    expect(result.success).toBe(true);
  });

  // Network rules
  it('accepts network allow with ports', () => {
    const result = PolicyDefinitionSchema.safeParse({
      network: [{ allow: ['registry.npmjs.org'], ports: [443] }],
    });
    expect(result.success).toBe(true);
  });

  it('accepts network deny wildcard', () => {
    const result = PolicyDefinitionSchema.safeParse({
      network: [{ deny: '*' }],
    });
    expect(result.success).toBe(true);
  });

  it('accepts network redirect rule', () => {
    const result = PolicyDefinitionSchema.safeParse({
      network: [{ redirect: 'prod.api.com', to: 'localhost:8080' }],
    });
    expect(result.success).toBe(true);
  });

  it('accepts network allowCidrs rule', () => {
    const result = PolicyDefinitionSchema.safeParse({
      network: [{ allowCidrs: ['127.0.0.1/32', '::1/128'] }],
    });
    expect(result.success).toBe(true);
  });

  it('accepts network allowCidrs with ports', () => {
    const result = PolicyDefinitionSchema.safeParse({
      network: [{ allowCidrs: ['10.0.0.0/8'], ports: [443, 80] }],
    });
    expect(result.success).toBe(true);
  });

  it('accepts network denyCidrs rule', () => {
    const result = PolicyDefinitionSchema.safeParse({
      network: [{ denyCidrs: ['169.254.169.254/32', '100.100.100.200/32'] }],
    });
    expect(result.success).toBe(true);
  });

  it('rejects network denyCidrs with extra fields', () => {
    const result = PolicyDefinitionSchema.safeParse({
      network: [{ denyCidrs: ['10.0.0.0/8'], extra: true }],
    });
    expect(result.success).toBe(false);
  });

  // Extended file ops (FileOpSchema is now z.string())
  it('accepts extended file ops (open, stat, list, readlink, mkdir, chmod, rename)', () => {
    const result = PolicyDefinitionSchema.safeParse({
      file: [{ allow: '/workspace/**', ops: ['read', 'write', 'open', 'stat', 'list', 'readlink', 'mkdir', 'chmod', 'rename'] }],
    });
    expect(result.success).toBe(true);
  });

  // Command rules
  it('accepts command allow rule', () => {
    const result = PolicyDefinitionSchema.safeParse({
      commands: [{ allow: ['node', 'npm'] }],
    });
    expect(result.success).toBe(true);
  });

  it('accepts command deny list', () => {
    const result = PolicyDefinitionSchema.safeParse({
      commands: [{ deny: ['env', 'printenv'] }],
    });
    expect(result.success).toBe(true);
  });

  it('accepts command redirect with string target', () => {
    const result = PolicyDefinitionSchema.safeParse({
      commands: [{ redirect: 'curl', to: '/usr/local/bin/safe-curl' }],
    });
    expect(result.success).toBe(true);
  });

  it('accepts command redirect with object target', () => {
    const result = PolicyDefinitionSchema.safeParse({
      commands: [{ redirect: ['curl', 'wget'], to: { cmd: 'agentsh-fetch', args: ['--audit'] } }],
    });
    expect(result.success).toBe(true);
  });

  // Env rules
  it('accepts env rules', () => {
    const result = PolicyDefinitionSchema.safeParse({
      env: [{ commands: ['node'], allow: ['PATH', 'HOME'] }],
    });
    expect(result.success).toBe(true);
  });

  it('accepts env rules with deny', () => {
    const result = PolicyDefinitionSchema.safeParse({
      env: [{ commands: ['node'], deny: ['SECRET_KEY'] }],
    });
    expect(result.success).toBe(true);
  });

  // DNS/Connect redirects
  it('accepts dns redirects', () => {
    const result = PolicyDefinitionSchema.safeParse({
      dns: [{ match: '.*\\.example\\.com', resolveTo: '127.0.0.1' }],
    });
    expect(result.success).toBe(true);
  });

  it('accepts connect redirects', () => {
    const result = PolicyDefinitionSchema.safeParse({
      connect: [{ match: 'api.prod.com:443', redirectTo: 'localhost:8080' }],
    });
    expect(result.success).toBe(true);
  });

  // Empty / full policy
  it('accepts empty policy', () => {
    const result = PolicyDefinitionSchema.safeParse({});
    expect(result.success).toBe(true);
  });

  it('accepts full agentDefault-style policy', () => {
    const result = PolicyDefinitionSchema.safeParse({
      file: [
        { allow: '/workspace/**', ops: ['read', 'write', 'create'] },
        { deny: ['/workspace/.git/config', '/workspace/.netrc'] },
        { deny: ['**/.env', '**/.env.*', '**/credentials*', '~/.ssh/**'] },
        { deny: '/proc/*/environ' },
      ],
      network: [
        { allow: ['registry.npmjs.org', 'registry.yarnpkg.com', 'pypi.org', 'files.pythonhosted.org'], ports: [443] },
        { deny: '*' },
      ],
      commands: [
        { deny: ['env', 'printenv', 'sudo', 'su', 'doas'] },
        { deny: ['shutdown', 'reboot', 'halt', 'poweroff'] },
        { deny: ['nc', 'ncat', 'netcat', 'socat', 'telnet'] },
        { deny: ['git push --force', 'git reset --hard'] },
        { redirect: ['curl', 'wget'], to: { cmd: 'agentsh-fetch', args: ['--audit'] } },
      ],
    });
    expect(result.success).toBe(true);
  });

  // Rejections
  it('rejects file rule with no decision key', () => {
    const result = PolicyDefinitionSchema.safeParse({
      file: [{ paths: '/workspace/**' }],
    });
    expect(result.success).toBe(false);
  });

  it('rejects unknown top-level key', () => {
    const result = PolicyDefinitionSchema.safeParse({
      file: [{ allow: '/workspace/**' }],
      unknown: 'field',
    });
    expect(result.success).toBe(false);
  });

  // ─── envPolicy ───────────────────────────────────────────

  it('accepts valid envPolicy', () => {
    const result = PolicyDefinitionSchema.safeParse({
      envPolicy: {
        deny: ['*_SECRET*', '*_PASSWORD*'],
        blockIteration: true,
      },
    });
    expect(result.success).toBe(true);
  });

  it('accepts envPolicy with allow, deny, maxBytes, maxKeys', () => {
    const result = PolicyDefinitionSchema.safeParse({
      envPolicy: {
        allow: ['PATH', 'HOME'],
        deny: ['SECRET_KEY'],
        maxBytes: 1024,
        maxKeys: 50,
        blockIteration: false,
      },
    });
    expect(result.success).toBe(true);
  });

  it('accepts empty envPolicy', () => {
    const result = PolicyDefinitionSchema.safeParse({
      envPolicy: {},
    });
    expect(result.success).toBe(true);
  });

  it('rejects envPolicy with unknown fields', () => {
    const result = PolicyDefinitionSchema.safeParse({
      envPolicy: { deny: ['*'], extra: true },
    });
    expect(result.success).toBe(false);
  });

  // ─── signalRules ─────────────────────────────────────────

  it('accepts valid signalRules', () => {
    const result = PolicyDefinitionSchema.safeParse({
      signalRules: [
        { name: 'allow-self', signals: ['@all'], target: { type: 'self' }, decision: 'allow' },
        { name: 'deny-external', signals: ['@fatal'], target: { type: 'external' }, decision: 'deny', fallback: 'audit', message: 'Blocked' },
      ],
    });
    expect(result.success).toBe(true);
  });

  it('accepts all signal target types', () => {
    for (const type of ['self', 'children', 'session', 'parent', 'external', 'system'] as const) {
      const result = PolicyDefinitionSchema.safeParse({
        signalRules: [{ name: `test-${type}`, signals: ['SIGTERM'], target: { type }, decision: 'allow' }],
      });
      expect(result.success).toBe(true);
    }
  });

  it('rejects signalRule with unknown target type', () => {
    const result = PolicyDefinitionSchema.safeParse({
      signalRules: [{ name: 'bad', signals: ['SIGTERM'], target: { type: 'invalid' }, decision: 'allow' }],
    });
    expect(result.success).toBe(false);
  });

  it('rejects signalRule without name', () => {
    const result = PolicyDefinitionSchema.safeParse({
      signalRules: [{ signals: ['SIGTERM'], target: { type: 'self' }, decision: 'allow' }],
    });
    expect(result.success).toBe(false);
  });

  // ─── unixSocketRules ─────────────────────────────────────

  it('accepts valid unixSocketRules', () => {
    const result = PolicyDefinitionSchema.safeParse({
      unixSocketRules: [
        { name: 'allow-docker', paths: ['/var/run/docker.sock'], operations: ['connect'], decision: 'allow' },
        { name: 'deny-system', paths: ['/var/run/**'], decision: 'deny', message: 'Blocked' },
      ],
    });
    expect(result.success).toBe(true);
  });

  it('rejects unixSocketRule with invalid decision', () => {
    const result = PolicyDefinitionSchema.safeParse({
      unixSocketRules: [{ name: 'bad', paths: ['/x'], decision: 'audit' }],
    });
    expect(result.success).toBe(false);
  });

  // ─── resourceLimits ──────────────────────────────────────

  it('accepts valid resourceLimits', () => {
    const result = PolicyDefinitionSchema.safeParse({
      resourceLimits: {
        maxMemoryMb: 8192,
        cpuQuotaPercent: 100,
        pidsMax: 500,
        commandTimeout: '15m',
        sessionTimeout: '12h',
        idleTimeout: '30m',
      },
    });
    expect(result.success).toBe(true);
  });

  it('accepts empty resourceLimits', () => {
    const result = PolicyDefinitionSchema.safeParse({ resourceLimits: {} });
    expect(result.success).toBe(true);
  });

  it('rejects resourceLimits with unknown fields', () => {
    const result = PolicyDefinitionSchema.safeParse({
      resourceLimits: { maxMemoryMb: 1024, extra: true },
    });
    expect(result.success).toBe(false);
  });

  // ─── auditSettings ──────────────────────────────────────

  it('accepts valid auditSettings', () => {
    const result = PolicyDefinitionSchema.safeParse({
      auditSettings: {
        logAllowed: false,
        logDenied: true,
        logApproved: true,
        includeStdout: false,
        includeStderr: true,
      },
    });
    expect(result.success).toBe(true);
  });

  it('accepts empty auditSettings', () => {
    const result = PolicyDefinitionSchema.safeParse({ auditSettings: {} });
    expect(result.success).toBe(true);
  });

  it('rejects auditSettings with unknown fields', () => {
    const result = PolicyDefinitionSchema.safeParse({
      auditSettings: { logDenied: true, extra: 'field' },
    });
    expect(result.success).toBe(false);
  });

  // Port validation
  it('rejects port 0', () => {
    const result = PolicyDefinitionSchema.safeParse({
      network: [{ allow: 'example.com', ports: [0] }],
    });
    expect(result.success).toBe(false);
  });

  it('rejects port 65536', () => {
    const result = PolicyDefinitionSchema.safeParse({
      network: [{ allow: 'example.com', ports: [65536] }],
    });
    expect(result.success).toBe(false);
  });

  it('accepts port 443', () => {
    const result = PolicyDefinitionSchema.safeParse({
      network: [{ allow: 'example.com', ports: [443] }],
    });
    expect(result.success).toBe(true);
  });

  it('accepts port 65535', () => {
    const result = PolicyDefinitionSchema.safeParse({
      network: [{ allow: 'example.com', ports: [65535] }],
    });
    expect(result.success).toBe(true);
  });

  // CommandRedirectTarget strict
  it('rejects command redirect target with extra properties', () => {
    const result = PolicyDefinitionSchema.safeParse({
      commands: [{ redirect: 'curl', to: { cmd: 'foo', args: [], extra: 'bar' } }],
    });
    expect(result.success).toBe(false);
  });

  // Package rules
  it('accepts valid package rule with match and action', () => {
    const result = PolicyDefinitionSchema.safeParse({
      packageRules: [
        { match: { packages: ['lodash'] }, action: 'allow' },
      ],
    });
    expect(result.success).toBe(true);
  });

  it('accepts package rule with all match fields', () => {
    const result = PolicyDefinitionSchema.safeParse({
      packageRules: [
        {
          match: {
            packages: ['lodash', 'express'],
            namePatterns: ['@evil/*'],
            findingType: 'malware',
            severity: 'critical',
            reasons: ['known-malware'],
            licenseSpdx: { allow: ['MIT', 'Apache-2.0'], deny: ['GPL-3.0'] },
            ecosystem: 'npm',
            options: { customKey: true },
          },
          action: 'block',
          reason: 'Known malicious package',
        },
      ],
    });
    expect(result.success).toBe(true);
  });

  it('accepts package rule with severity as array', () => {
    const result = PolicyDefinitionSchema.safeParse({
      packageRules: [
        { match: { severity: ['critical', 'high'] }, action: 'block' },
      ],
    });
    expect(result.success).toBe(true);
  });

  it('accepts package rule with severity as string', () => {
    const result = PolicyDefinitionSchema.safeParse({
      packageRules: [
        { match: { severity: 'critical' }, action: 'block' },
      ],
    });
    expect(result.success).toBe(true);
  });

  it('accepts package rule with empty match (matches all)', () => {
    const result = PolicyDefinitionSchema.safeParse({
      packageRules: [
        { match: {}, action: 'warn' },
      ],
    });
    expect(result.success).toBe(true);
  });

  it('accepts package rule with reason', () => {
    const result = PolicyDefinitionSchema.safeParse({
      packageRules: [
        { match: { packages: ['is-odd'] }, action: 'warn', reason: 'Unnecessary micro-dependency' },
      ],
    });
    expect(result.success).toBe(true);
  });

  it('accepts package rule with licenseSpdx allow only', () => {
    const result = PolicyDefinitionSchema.safeParse({
      packageRules: [
        { match: { licenseSpdx: { allow: ['MIT'] } }, action: 'allow' },
      ],
    });
    expect(result.success).toBe(true);
  });

  it('accepts package rule with licenseSpdx deny only', () => {
    const result = PolicyDefinitionSchema.safeParse({
      packageRules: [
        { match: { licenseSpdx: { deny: ['AGPL-3.0'] } }, action: 'block' },
      ],
    });
    expect(result.success).toBe(true);
  });

  it('accepts all four package rule actions', () => {
    for (const action of ['allow', 'warn', 'approve', 'block'] as const) {
      const result = PolicyDefinitionSchema.safeParse({
        packageRules: [{ match: {}, action }],
      });
      expect(result.success).toBe(true);
    }
  });

  it('rejects package rule with invalid action', () => {
    const result = PolicyDefinitionSchema.safeParse({
      packageRules: [
        { match: {}, action: 'deny' },
      ],
    });
    expect(result.success).toBe(false);
  });

  it('rejects package rule without match', () => {
    const result = PolicyDefinitionSchema.safeParse({
      packageRules: [
        { action: 'allow' },
      ],
    });
    expect(result.success).toBe(false);
  });

  it('rejects package rule without action', () => {
    const result = PolicyDefinitionSchema.safeParse({
      packageRules: [
        { match: { packages: ['lodash'] } },
      ],
    });
    expect(result.success).toBe(false);
  });

  it('rejects package match with unknown field', () => {
    const result = PolicyDefinitionSchema.safeParse({
      packageRules: [
        { match: { packages: ['lodash'], unknownField: 'value' }, action: 'allow' },
      ],
    });
    expect(result.success).toBe(false);
  });

  it('rejects package rule with extra properties', () => {
    const result = PolicyDefinitionSchema.safeParse({
      packageRules: [
        { match: {}, action: 'allow', extra: 'field' },
      ],
    });
    expect(result.success).toBe(false);
  });

  it('rejects licenseSpdx with extra properties', () => {
    const result = PolicyDefinitionSchema.safeParse({
      packageRules: [
        { match: { licenseSpdx: { allow: ['MIT'], extra: true } }, action: 'allow' },
      ],
    });
    expect(result.success).toBe(false);
  });

  it('accepts multiple package rules', () => {
    const result = PolicyDefinitionSchema.safeParse({
      packageRules: [
        { match: { findingType: 'malware' }, action: 'block', reason: 'Block malware' },
        { match: { severity: 'critical' }, action: 'block' },
        { match: { licenseSpdx: { deny: ['GPL-3.0'] } }, action: 'warn' },
        { match: {}, action: 'allow' },
      ],
    });
    expect(result.success).toBe(true);
  });

  it('accepts empty packageRules array', () => {
    const result = PolicyDefinitionSchema.safeParse({
      packageRules: [],
    });
    expect(result.success).toBe(true);
  });
});

describe('validatePolicy', () => {
  it('returns valid policy', () => {
    const policy = validatePolicy({ file: [{ allow: '/workspace/**' }] });
    expect(policy.file).toHaveLength(1);
  });

  it('throws PolicyValidationError on invalid input', () => {
    expect(() => validatePolicy({ file: [{ invalid: true }] })).toThrow(PolicyValidationError);
  });
});
