import { describe, it, expect } from 'vitest';
import { DatabaseConnectionRuleSchema, DatabaseRuleSchema, DbServiceDefSchema, PolicyDefinitionSchema, validatePolicy } from './schema.js';
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

  // ─── providers (secret providers) ─────────────────────────

  it('accepts providers with keyring type', () => {
    const result = PolicyDefinitionSchema.safeParse({
      providers: { local: { type: 'keyring' } },
    });
    expect(result.success).toBe(true);
  });

  it('accepts providers with vault type and auth', () => {
    const result = PolicyDefinitionSchema.safeParse({
      providers: {
        myVault: {
          type: 'vault',
          address: 'https://vault.internal',
          namespace: 'team-a',
          auth: { method: 'token', tokenRef: 'keyring://agentsh/vault-token' },
        },
      },
    });
    expect(result.success).toBe(true);
  });

  it('accepts vault provider with approle auth', () => {
    const result = PolicyDefinitionSchema.safeParse({
      providers: {
        v: {
          type: 'vault',
          address: 'https://vault.internal',
          auth: { method: 'approle', roleId: 'r1', secretIdRef: 'keyring://agentsh/sid' },
        },
      },
    });
    expect(result.success).toBe(true);
  });

  it('accepts vault provider with kubernetes auth', () => {
    const result = PolicyDefinitionSchema.safeParse({
      providers: {
        v: {
          type: 'vault',
          address: 'https://vault.internal',
          auth: { method: 'kubernetes', kubeRole: 'agentsh', kubeMountPath: 'kubernetes', kubeTokenPath: '/var/run/secrets/kubernetes.io/serviceaccount/token' },
        },
      },
    });
    expect(result.success).toBe(true);
  });

  it('accepts providers with aws-sm type', () => {
    const result = PolicyDefinitionSchema.safeParse({
      providers: { aws: { type: 'aws-sm', region: 'us-east-1' } },
    });
    expect(result.success).toBe(true);
  });

  it('accepts providers with gcp-sm type', () => {
    const result = PolicyDefinitionSchema.safeParse({
      providers: { gcp: { type: 'gcp-sm', projectId: 'my-project' } },
    });
    expect(result.success).toBe(true);
  });

  it('accepts providers with azure-kv type', () => {
    const result = PolicyDefinitionSchema.safeParse({
      providers: { azure: { type: 'azure-kv', vaultUrl: 'https://myvault.vault.azure.net' } },
    });
    expect(result.success).toBe(true);
  });

  it('accepts providers with op type', () => {
    const result = PolicyDefinitionSchema.safeParse({
      providers: { onepass: { type: 'op', serverUrl: 'https://op.internal', apiKeyRef: 'keyring://agentsh/op_key' } },
    });
    expect(result.success).toBe(true);
  });

  it('accepts multiple providers', () => {
    const result = PolicyDefinitionSchema.safeParse({
      providers: {
        kr: { type: 'keyring' },
        aws: { type: 'aws-sm', region: 'us-east-1' },
        v: { type: 'vault', address: 'https://vault.internal' },
      },
    });
    expect(result.success).toBe(true);
  });

  it('rejects provider with unknown type', () => {
    const result = PolicyDefinitionSchema.safeParse({
      providers: { bad: { type: 'unknown-type' } },
    });
    expect(result.success).toBe(false);
  });

  it('rejects vault provider without required address', () => {
    const result = PolicyDefinitionSchema.safeParse({
      providers: { bad: { type: 'vault' } },
    });
    expect(result.success).toBe(false);
  });

  it('rejects aws-sm provider without required region', () => {
    const result = PolicyDefinitionSchema.safeParse({
      providers: { bad: { type: 'aws-sm' } },
    });
    expect(result.success).toBe(false);
  });

  it('rejects op provider without required serverUrl', () => {
    const result = PolicyDefinitionSchema.safeParse({
      providers: { bad: { type: 'op' } },
    });
    expect(result.success).toBe(false);
  });

  it('accepts empty providers map', () => {
    const result = PolicyDefinitionSchema.safeParse({ providers: {} });
    expect(result.success).toBe(true);
  });

  // ─── httpServices ──────────────────────────────────────────

  it('accepts httpService with filtering rules only', () => {
    const result = PolicyDefinitionSchema.safeParse({
      httpServices: [{
        name: 'internal-api',
        upstream: 'https://api.internal.corp',
        default: 'deny',
        rules: [
          { name: 'read-only', methods: ['GET'], paths: ['/**'], decision: 'allow' },
        ],
      }],
    });
    expect(result.success).toBe(true);
  });

  it('accepts httpService with credentials and rules', () => {
    const result = PolicyDefinitionSchema.safeParse({
      httpServices: [{
        name: 'github',
        upstream: 'https://api.github.com',
        exposeAs: 'GITHUB_API_URL',
        aliases: ['api.github.com'],
        allowDirect: false,
        default: 'deny',
        secret: { ref: 'vault://kv/data/github#token', format: 'ghp_{rand:36}' },
        inject: { header: { name: 'Authorization', template: 'Bearer {{secret}}' } },
        scrubResponse: true,
        rules: [
          { name: 'read-issues', methods: ['GET'], paths: ['/repos/*/*/issues'], decision: 'allow' },
          { name: 'create-issue', methods: ['POST'], paths: ['/repos/*/*/issues'], decision: 'approve', message: 'Approve issue creation?', timeout: '5m' },
        ],
      }],
    });
    expect(result.success).toBe(true);
  });

  it('accepts httpService with credentials only (no rules)', () => {
    const result = PolicyDefinitionSchema.safeParse({
      httpServices: [{
        name: 'anthropic',
        upstream: 'https://api.anthropic.com',
        secret: { ref: 'keyring://agentsh/anthropic_key', format: 'sk-ant-{rand:93}' },
        inject: { header: { name: 'x-api-key', template: '{{secret}}' } },
      }],
    });
    expect(result.success).toBe(true);
  });

  it('accepts httpService with only required fields', () => {
    const result = PolicyDefinitionSchema.safeParse({
      httpServices: [{ name: 'minimal', upstream: 'https://api.example.com' }],
    });
    expect(result.success).toBe(true);
  });

  it('accepts all httpService rule decisions', () => {
    for (const decision of ['allow', 'deny', 'approve', 'audit'] as const) {
      const result = PolicyDefinitionSchema.safeParse({
        httpServices: [{
          name: `test-${decision}`,
          upstream: 'https://api.example.com',
          rules: [{ name: `rule-${decision}`, paths: ['/**'], decision }],
        }],
      });
      expect(result.success).toBe(true);
    }
  });

  it('rejects httpService rule without paths', () => {
    const result = PolicyDefinitionSchema.safeParse({
      httpServices: [{
        name: 'test',
        upstream: 'https://api.example.com',
        rules: [{ name: 'bad', decision: 'allow' }],
      }],
    });
    expect(result.success).toBe(false);
  });

  it('rejects httpService rule without name', () => {
    const result = PolicyDefinitionSchema.safeParse({
      httpServices: [{
        name: 'test',
        upstream: 'https://api.example.com',
        rules: [{ paths: ['/**'], decision: 'allow' }],
      }],
    });
    expect(result.success).toBe(false);
  });

  it('rejects httpService without name', () => {
    const result = PolicyDefinitionSchema.safeParse({
      httpServices: [{ upstream: 'https://api.example.com' }],
    });
    expect(result.success).toBe(false);
  });

  it('rejects httpService without upstream', () => {
    const result = PolicyDefinitionSchema.safeParse({
      httpServices: [{ name: 'test' }],
    });
    expect(result.success).toBe(false);
  });

  it('rejects httpService with invalid default', () => {
    const result = PolicyDefinitionSchema.safeParse({
      httpServices: [{ name: 'test', upstream: 'https://x.com', default: 'audit' }],
    });
    expect(result.success).toBe(false);
  });

  it('rejects httpService with unknown field', () => {
    const result = PolicyDefinitionSchema.safeParse({
      httpServices: [{ name: 'test', upstream: 'https://x.com', extra: true }],
    });
    expect(result.success).toBe(false);
  });

  it('accepts empty httpServices array', () => {
    const result = PolicyDefinitionSchema.safeParse({ httpServices: [] });
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

describe('DbServiceDefSchema', () => {
  it('accepts a minimal Postgres terminate_reissue service', () => {
    const result = DbServiceDefSchema.safeParse({
      family: 'postgres',
      dialect: 'postgres',
      upstream: '127.0.0.1:5432',
      tlsMode: 'terminate_reissue',
    });
    expect(result.success).toBe(true);
  });

  it('accepts all optional flags', () => {
    const result = DbServiceDefSchema.safeParse({
      family: 'postgres',
      dialect: 'aurora_postgres',
      upstream: 'db.local:5432',
      tlsMode: 'terminate_plaintext_upstream',
      allowFunctionCallProtocol: true,
      allowGssEncryption: false,
      trustedNetwork: true,
    });
    expect(result.success).toBe(true);
  });

  it('rejects an unknown tlsMode', () => {
    const result = DbServiceDefSchema.safeParse({
      family: 'postgres',
      dialect: 'postgres',
      upstream: '127.0.0.1:5432',
      tlsMode: 'bogus',
    });
    expect(result.success).toBe(false);
  });

  it('requires family, dialect, upstream, tlsMode', () => {
    const result = DbServiceDefSchema.safeParse({ family: 'postgres' });
    expect(result.success).toBe(false);
  });

  it('preserves unknown forward-compat fields via passthrough', () => {
    const result = DbServiceDefSchema.safeParse({
      family: 'postgres',
      dialect: 'postgres',
      upstream: '127.0.0.1:5432',
      tlsMode: 'passthrough',
      newFutureField: 'whatever',
    });
    expect(result.success).toBe(true);
    if (result.success) {
      expect((result.data as any).newFutureField).toBe('whatever');
    }
  });
});

describe('DatabaseRuleSchema', () => {
  const minimal = {
    name: 'allow-reads',
    operations: ['read'],
    decision: 'allow' as const,
  };

  it('accepts a minimal rule', () => {
    const result = DatabaseRuleSchema.safeParse(minimal);
    expect(result.success).toBe(true);
  });

  it('accepts every documented enum value for decision', () => {
    for (const decision of ['allow', 'deny', 'approve', 'audit', 'redirect'] as const) {
      const result = DatabaseRuleSchema.safeParse({
        name: `r-${decision}`,
        operations: ['read'],
        decision,
        ...(decision === 'redirect' ? { redirect: { relation: 'public.canonical' } } : {}),
      });
      expect(result.success).toBe(true);
    }
  });

  it('rejects unknown decision values', () => {
    const result = DatabaseRuleSchema.safeParse({
      ...minimal,
      decision: 'maybe',
    });
    expect(result.success).toBe(false);
  });

  it('accepts every documented matchObjectResolution value', () => {
    for (const tag of [
      'qualified_syntactic',
      'unqualified_syntactic',
      'ambiguous_after_search_path',
      'maybe_temp_shadowed',
      'unresolved',
      'catalog_resolved',
      '*',
    ] as const) {
      const result = DatabaseRuleSchema.safeParse({
        ...minimal,
        matchObjectResolution: tag,
      });
      expect(result.success).toBe(true);
    }
  });

  it('accepts denyModeInTx enum values', () => {
    for (const m of ['terminate', 'rollback_then_continue'] as const) {
      const result = DatabaseRuleSchema.safeParse({ ...minimal, denyModeInTx: m });
      expect(result.success).toBe(true);
    }
  });

  it('accepts open-vocab operations (not constrained to a fixed enum)', () => {
    const result = DatabaseRuleSchema.safeParse({
      ...minimal,
      operations: ['my_future_operation_name'],
    });
    expect(result.success).toBe(true);
  });

  it('accepts open-vocab subtypes', () => {
    const result = DatabaseRuleSchema.safeParse({
      ...minimal,
      subtypes: ['my_subtype'],
    });
    expect(result.success).toBe(true);
  });

  it('preserves unknown forward-compat fields via passthrough', () => {
    const result = DatabaseRuleSchema.safeParse({
      ...minimal,
      newFutureField: 42,
    });
    expect(result.success).toBe(true);
    if (result.success) {
      expect((result.data as any).newFutureField).toBe(42);
    }
  });
});

describe('DatabaseConnectionRuleSchema', () => {
  const minimal = {
    name: 'allow-connects',
    decision: 'allow' as const,
  };

  it('accepts a minimal rule', () => {
    const result = DatabaseConnectionRuleSchema.safeParse(minimal);
    expect(result.success).toBe(true);
  });

  it('accepts all matchKind values', () => {
    for (const k of ['connect', 'cancel', 'replication'] as const) {
      const result = DatabaseConnectionRuleSchema.safeParse({ ...minimal, matchKind: k });
      expect(result.success).toBe(true);
    }
  });

  it('accepts decision enum without redirect', () => {
    for (const d of ['allow', 'deny', 'approve', 'audit'] as const) {
      const result = DatabaseConnectionRuleSchema.safeParse({ ...minimal, decision: d });
      expect(result.success).toBe(true);
    }
  });

  it('rejects decision: redirect (not supported on connection rules)', () => {
    const result = DatabaseConnectionRuleSchema.safeParse({
      ...minimal,
      decision: 'redirect',
    });
    expect(result.success).toBe(false);
  });

  it('accepts all visibility-restricted optional fields', () => {
    const result = DatabaseConnectionRuleSchema.safeParse({
      ...minimal,
      dbService: 'pg-main',
      dbUser: ['app', 'reader'],
      database: 'production',
      applicationName: 'web-*',
      clientIdentity: 'spiffe://cluster/agent',
      message: 'denied',
      timeout: '60s',
    });
    expect(result.success).toBe(true);
  });

  it('preserves unknown forward-compat fields via passthrough', () => {
    const result = DatabaseConnectionRuleSchema.safeParse({
      ...minimal,
      newFutureField: 'whatever',
    });
    expect(result.success).toBe(true);
    if (result.success) {
      expect((result.data as any).newFutureField).toBe('whatever');
    }
  });
});

describe('PolicyDefinitionSchema — DB top-level keys', () => {
  it('accepts dbServices as a record of DbServiceDef', () => {
    const result = PolicyDefinitionSchema.safeParse({
      dbServices: {
        'pg-main': {
          family: 'postgres',
          dialect: 'postgres',
          upstream: '127.0.0.1:5432',
          tlsMode: 'terminate_reissue',
        },
      },
    });
    expect(result.success).toBe(true);
  });

  it('accepts databaseRules array', () => {
    const result = PolicyDefinitionSchema.safeParse({
      databaseRules: [
        { name: 'r1', operations: ['read'], decision: 'allow' },
      ],
    });
    expect(result.success).toBe(true);
  });

  it('accepts databaseConnectionRules array', () => {
    const result = PolicyDefinitionSchema.safeParse({
      databaseConnectionRules: [
        { name: 'c1', decision: 'allow' },
      ],
    });
    expect(result.success).toBe(true);
  });

  it('accepts a policy with all three DB sections plus existing sections', () => {
    const result = PolicyDefinitionSchema.safeParse({
      file: [{ allow: '/workspace/**' }],
      dbServices: { 'pg': { family: 'postgres', dialect: 'postgres', upstream: 'h:5432', tlsMode: 'terminate_reissue' } },
      databaseRules: [{ name: 'r', operations: ['read'], decision: 'allow' }],
      databaseConnectionRules: [{ name: 'c', decision: 'allow' }],
    });
    expect(result.success).toBe(true);
  });
});
