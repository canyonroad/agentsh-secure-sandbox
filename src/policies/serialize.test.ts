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

  it('serializes network allowCidrs rule', () => {
    const result = serializePolicy({
      network: [{ allowCidrs: ['127.0.0.1/32', '::1/128'] }],
    });
    const parsed = yaml.load(result) as any;
    expect(parsed.network_rules).toHaveLength(1);
    expect(parsed.network_rules[0].cidrs).toEqual(['127.0.0.1/32', '::1/128']);
    expect(parsed.network_rules[0].decision).toBe('allow');
    expect(parsed.network_rules[0].domains).toBeUndefined();
  });

  it('serializes network allowCidrs with ports', () => {
    const result = serializePolicy({
      network: [{ allowCidrs: ['10.0.0.0/8'], ports: [443] }],
    });
    const parsed = yaml.load(result) as any;
    expect(parsed.network_rules[0].cidrs).toEqual(['10.0.0.0/8']);
    expect(parsed.network_rules[0].ports).toEqual([443]);
    expect(parsed.network_rules[0].decision).toBe('allow');
  });

  it('serializes network denyCidrs rule', () => {
    const result = serializePolicy({
      network: [{ denyCidrs: ['169.254.169.254/32', '100.100.100.200/32'] }],
    });
    const parsed = yaml.load(result) as any;
    expect(parsed.network_rules).toHaveLength(1);
    expect(parsed.network_rules[0].cidrs).toEqual(['169.254.169.254/32', '100.100.100.200/32']);
    expect(parsed.network_rules[0].decision).toBe('deny');
    expect(parsed.network_rules[0].domains).toBeUndefined();
  });

  it('serializes mixed CIDR and domain network rules', () => {
    const result = serializePolicy({
      network: [
        { allowCidrs: ['127.0.0.1/32'] },
        { allow: ['registry.npmjs.org'], ports: [443] },
        { denyCidrs: ['169.254.169.254/32'] },
        { deny: '*' },
      ],
    });
    const parsed = yaml.load(result) as any;
    expect(parsed.network_rules).toHaveLength(4);
    expect(parsed.network_rules[0].cidrs).toEqual(['127.0.0.1/32']);
    expect(parsed.network_rules[1].domains).toEqual(['registry.npmjs.org']);
    expect(parsed.network_rules[2].cidrs).toEqual(['169.254.169.254/32']);
    expect(parsed.network_rules[3].domains).toEqual(['*']);
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
    expect(parsed.env_policy).toBeDefined();
    expect(parsed.signal_rules.length).toBeGreaterThan(0);
    expect(parsed.unix_socket_rules.length).toBeGreaterThan(0);
    expect(parsed.resource_limits).toBeDefined();
    expect(parsed.audit).toBeDefined();
  });

  // ─── envPolicy ──────────────────────────────────────────────

  it('serializes envPolicy with all fields', () => {
    const result = serializePolicy({
      envPolicy: {
        allow: ['PATH', 'HOME'],
        deny: ['*_SECRET*', '*_PASSWORD*'],
        maxBytes: 1024,
        maxKeys: 50,
        blockIteration: true,
      },
    });
    const parsed = yaml.load(result) as any;
    expect(parsed.env_policy.allow).toEqual(['PATH', 'HOME']);
    expect(parsed.env_policy.deny).toEqual(['*_SECRET*', '*_PASSWORD*']);
    expect(parsed.env_policy.max_bytes).toBe(1024);
    expect(parsed.env_policy.max_keys).toBe(50);
    expect(parsed.env_policy.block_iteration).toBe(true);
  });

  it('serializes envPolicy with only deny', () => {
    const result = serializePolicy({
      envPolicy: { deny: ['SECRET_KEY'] },
    });
    const parsed = yaml.load(result) as any;
    expect(parsed.env_policy.deny).toEqual(['SECRET_KEY']);
    expect(parsed.env_policy.allow).toBeUndefined();
    expect(parsed.env_policy.max_bytes).toBeUndefined();
  });

  it('omits env_policy when envPolicy is not set', () => {
    const result = serializePolicy({ file: [{ allow: '/workspace/**' }] });
    const parsed = yaml.load(result) as any;
    expect(parsed.env_policy).toBeUndefined();
  });

  // ─── signalRules ────────────────────────────────────────────

  it('serializes signalRules', () => {
    const result = serializePolicy({
      signalRules: [
        { name: 'allow-self', signals: ['@all'], target: { type: 'self' }, decision: 'allow' },
        { name: 'deny-ext', signals: ['@fatal'], target: { type: 'external' }, decision: 'deny', fallback: 'audit', message: 'Blocked' },
      ],
    });
    const parsed = yaml.load(result) as any;
    expect(parsed.signal_rules).toHaveLength(2);
    expect(parsed.signal_rules[0].name).toBe('allow-self');
    expect(parsed.signal_rules[0].signals).toEqual(['@all']);
    expect(parsed.signal_rules[0].target).toEqual({ type: 'self' });
    expect(parsed.signal_rules[0].decision).toBe('allow');
    expect(parsed.signal_rules[1].fallback).toBe('audit');
    expect(parsed.signal_rules[1].message).toBe('Blocked');
  });

  it('serializes signalRule with target pattern', () => {
    const result = serializePolicy({
      signalRules: [
        { name: 'test', signals: ['SIGTERM'], target: { type: 'external', pattern: 'nginx*' }, decision: 'deny' },
      ],
    });
    const parsed = yaml.load(result) as any;
    expect(parsed.signal_rules[0].target).toEqual({ type: 'external', pattern: 'nginx*' });
  });

  it('omits signal_rules when signalRules is empty', () => {
    const result = serializePolicy({ signalRules: [] });
    const parsed = yaml.load(result) as any;
    expect(parsed.signal_rules).toBeUndefined();
  });

  // ─── unixSocketRules ────────────────────────────────────────

  it('serializes unixSocketRules', () => {
    const result = serializePolicy({
      unixSocketRules: [
        { name: 'allow-docker', paths: ['/var/run/docker.sock'], operations: ['connect'], decision: 'allow' },
        { name: 'deny-system', paths: ['/var/run/**'], decision: 'deny', message: 'Blocked' },
      ],
    });
    const parsed = yaml.load(result) as any;
    expect(parsed.unix_socket_rules).toHaveLength(2);
    expect(parsed.unix_socket_rules[0].name).toBe('allow-docker');
    expect(parsed.unix_socket_rules[0].paths).toEqual(['/var/run/docker.sock']);
    expect(parsed.unix_socket_rules[0].operations).toEqual(['connect']);
    expect(parsed.unix_socket_rules[0].decision).toBe('allow');
    expect(parsed.unix_socket_rules[1].message).toBe('Blocked');
  });

  it('omits operations when not provided in unixSocketRule', () => {
    const result = serializePolicy({
      unixSocketRules: [
        { name: 'test', paths: ['/tmp/test.sock'], decision: 'deny' },
      ],
    });
    const parsed = yaml.load(result) as any;
    expect(parsed.unix_socket_rules[0].operations).toBeUndefined();
  });

  it('omits unix_socket_rules when unixSocketRules is empty', () => {
    const result = serializePolicy({ unixSocketRules: [] });
    const parsed = yaml.load(result) as any;
    expect(parsed.unix_socket_rules).toBeUndefined();
  });

  // ─── resourceLimits ─────────────────────────────────────────

  it('serializes resourceLimits with snake_case keys', () => {
    const result = serializePolicy({
      resourceLimits: {
        maxMemoryMb: 8192,
        cpuQuotaPercent: 100,
        pidsMax: 500,
        commandTimeout: '15m',
        sessionTimeout: '12h',
        idleTimeout: '30m',
      },
    });
    const parsed = yaml.load(result) as any;
    expect(parsed.resource_limits.max_memory_mb).toBe(8192);
    expect(parsed.resource_limits.cpu_quota_percent).toBe(100);
    expect(parsed.resource_limits.pids_max).toBe(500);
    expect(parsed.resource_limits.command_timeout).toBe('15m');
    expect(parsed.resource_limits.session_timeout).toBe('12h');
    expect(parsed.resource_limits.idle_timeout).toBe('30m');
  });

  it('serializes partial resourceLimits', () => {
    const result = serializePolicy({
      resourceLimits: { maxMemoryMb: 4096 },
    });
    const parsed = yaml.load(result) as any;
    expect(parsed.resource_limits.max_memory_mb).toBe(4096);
    expect(parsed.resource_limits.cpu_quota_percent).toBeUndefined();
  });

  it('omits resource_limits when not set', () => {
    const result = serializePolicy({ file: [{ allow: '/workspace/**' }] });
    const parsed = yaml.load(result) as any;
    expect(parsed.resource_limits).toBeUndefined();
  });

  // ─── auditSettings ─────────────────────────────────────────

  it('serializes auditSettings with snake_case keys', () => {
    const result = serializePolicy({
      auditSettings: {
        logAllowed: false,
        logDenied: true,
        logApproved: true,
        includeStdout: false,
        includeStderr: true,
      },
    });
    const parsed = yaml.load(result) as any;
    expect(parsed.audit.log_allowed).toBe(false);
    expect(parsed.audit.log_denied).toBe(true);
    expect(parsed.audit.log_approved).toBe(true);
    expect(parsed.audit.include_stdout).toBe(false);
    expect(parsed.audit.include_stderr).toBe(true);
  });

  it('serializes partial auditSettings', () => {
    const result = serializePolicy({
      auditSettings: { logDenied: true },
    });
    const parsed = yaml.load(result) as any;
    expect(parsed.audit.log_denied).toBe(true);
    expect(parsed.audit.log_allowed).toBeUndefined();
  });

  it('omits audit when auditSettings is not set', () => {
    const result = serializePolicy({ file: [{ allow: '/workspace/**' }] });
    const parsed = yaml.load(result) as any;
    expect(parsed.audit).toBeUndefined();
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

  // ─── providers (secret providers) ─────────────────────────

  it('serializes providers with multiple types', () => {
    const result = serializePolicy({
      providers: {
        local: { type: 'keyring' },
        aws: { type: 'aws-sm', region: 'us-east-1' },
        myVault: {
          type: 'vault',
          address: 'https://vault.internal',
          namespace: 'ns',
          auth: { method: 'token', tokenRef: 'keyring://agentsh/vt' },
        },
      },
    });
    const parsed = yaml.load(result) as any;
    expect(parsed.providers.local).toEqual({ type: 'keyring' });
    expect(parsed.providers.aws).toEqual({ type: 'aws-sm', region: 'us-east-1' });
    expect(parsed.providers.myVault).toEqual({
      type: 'vault',
      address: 'https://vault.internal',
      namespace: 'ns',
      auth: { method: 'token', token_ref: 'keyring://agentsh/vt' },
    });
  });

  it('serializes gcp-sm provider with snake_case', () => {
    const result = serializePolicy({
      providers: { gcp: { type: 'gcp-sm', projectId: 'my-project' } },
    });
    const parsed = yaml.load(result) as any;
    expect(parsed.providers.gcp).toEqual({ type: 'gcp-sm', project_id: 'my-project' });
  });

  it('serializes azure-kv provider with snake_case', () => {
    const result = serializePolicy({
      providers: { azure: { type: 'azure-kv', vaultUrl: 'https://myvault.vault.azure.net' } },
    });
    const parsed = yaml.load(result) as any;
    expect(parsed.providers.azure).toEqual({ type: 'azure-kv', vault_url: 'https://myvault.vault.azure.net' });
  });

  it('serializes op provider with snake_case', () => {
    const result = serializePolicy({
      providers: { onepass: { type: 'op', serverUrl: 'https://op.internal', apiKeyRef: 'keyring://agentsh/op_key' } },
    });
    const parsed = yaml.load(result) as any;
    expect(parsed.providers.onepass).toEqual({ type: 'op', server_url: 'https://op.internal', api_key_ref: 'keyring://agentsh/op_key' });
  });

  it('serializes vault provider with approle auth', () => {
    const result = serializePolicy({
      providers: {
        v: {
          type: 'vault',
          address: 'https://vault.internal',
          auth: { method: 'approle', roleId: 'r1', secretIdRef: 'keyring://agentsh/sid' },
        },
      },
    });
    const parsed = yaml.load(result) as any;
    expect(parsed.providers.v.auth).toEqual({ method: 'approle', role_id: 'r1', secret_id_ref: 'keyring://agentsh/sid' });
  });

  it('serializes vault provider with kubernetes auth', () => {
    const result = serializePolicy({
      providers: {
        v: {
          type: 'vault',
          address: 'https://vault.internal',
          auth: { method: 'kubernetes', kubeRole: 'agentsh', kubeMountPath: 'kubernetes' },
        },
      },
    });
    const parsed = yaml.load(result) as any;
    expect(parsed.providers.v.auth).toEqual({ method: 'kubernetes', kube_role: 'agentsh', kube_mount_path: 'kubernetes' });
  });

  it('omits providers when empty', () => {
    const result = serializePolicy({ providers: {} });
    const parsed = yaml.load(result) as any;
    expect(parsed.providers).toBeUndefined();
  });

  it('omits providers when not set', () => {
    const result = serializePolicy({ file: [{ allow: '/workspace/**' }] });
    const parsed = yaml.load(result) as any;
    expect(parsed.providers).toBeUndefined();
  });

  // ─── httpServices ─────────────────────────────────────────

  it('serializes httpService with credentials and rules', () => {
    const result = serializePolicy({
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
          { name: 'deny-rest', paths: ['/**'], decision: 'deny', message: 'Blocked' },
        ],
      }],
    });
    const parsed = yaml.load(result) as any;
    expect(parsed.http_services).toHaveLength(1);
    const svc = parsed.http_services[0];
    expect(svc.name).toBe('github');
    expect(svc.upstream).toBe('https://api.github.com');
    expect(svc.expose_as).toBe('GITHUB_API_URL');
    expect(svc.aliases).toEqual(['api.github.com']);
    expect(svc.allow_direct).toBe(false);
    expect(svc.default).toBe('deny');
    expect(svc.secret).toEqual({ ref: 'vault://kv/data/github#token', format: 'ghp_{rand:36}' });
    expect(svc.inject).toEqual({ header: { name: 'Authorization', template: 'Bearer {{secret}}' } });
    expect(svc.scrub_response).toBe(true);
    expect(svc.rules).toHaveLength(2);
    expect(svc.rules[0]).toEqual({ name: 'read-issues', methods: ['GET'], paths: ['/repos/*/*/issues'], decision: 'allow' });
    expect(svc.rules[1]).toEqual({ name: 'deny-rest', paths: ['/**'], decision: 'deny', message: 'Blocked' });
  });

  it('serializes httpService with only required fields', () => {
    const result = serializePolicy({
      httpServices: [{ name: 'minimal', upstream: 'https://api.example.com' }],
    });
    const parsed = yaml.load(result) as any;
    expect(parsed.http_services).toHaveLength(1);
    expect(parsed.http_services[0].name).toBe('minimal');
    expect(parsed.http_services[0].upstream).toBe('https://api.example.com');
    expect(parsed.http_services[0].expose_as).toBeUndefined();
    expect(parsed.http_services[0].rules).toBeUndefined();
    expect(parsed.http_services[0].secret).toBeUndefined();
  });

  it('serializes httpService rule with timeout', () => {
    const result = serializePolicy({
      httpServices: [{
        name: 'test',
        upstream: 'https://api.example.com',
        rules: [{ name: 'approve-it', methods: ['POST'], paths: ['/action'], decision: 'approve', timeout: '5m' }],
      }],
    });
    const parsed = yaml.load(result) as any;
    expect(parsed.http_services[0].rules[0].timeout).toBe('5m');
  });

  it('serializes credentials-only httpService', () => {
    const result = serializePolicy({
      httpServices: [{
        name: 'anthropic',
        upstream: 'https://api.anthropic.com',
        secret: { ref: 'keyring://agentsh/key', format: 'sk-ant-{rand:93}' },
        inject: { header: { name: 'x-api-key', template: '{{secret}}' } },
      }],
    });
    const parsed = yaml.load(result) as any;
    const svc = parsed.http_services[0];
    expect(svc.secret).toEqual({ ref: 'keyring://agentsh/key', format: 'sk-ant-{rand:93}' });
    expect(svc.inject).toEqual({ header: { name: 'x-api-key', template: '{{secret}}' } });
    expect(svc.rules).toBeUndefined();
  });

  it('omits http_services when httpServices is empty', () => {
    const result = serializePolicy({ httpServices: [] });
    const parsed = yaml.load(result) as any;
    expect(parsed.http_services).toBeUndefined();
  });

  it('omits http_services when not set', () => {
    const result = serializePolicy({ file: [{ allow: '/workspace/**' }] });
    const parsed = yaml.load(result) as any;
    expect(parsed.http_services).toBeUndefined();
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

describe('serializePolicy — dbServices', () => {
  it('emits db_services with snake_case tls_mode', () => {
    const result = serializePolicy({
      dbServices: {
        'pg-main': {
          family: 'postgres',
          dialect: 'postgres',
          upstream: '127.0.0.1:5432',
          tlsMode: 'terminate_reissue',
        },
      },
    });
    const parsed = yaml.load(result) as any;
    expect(parsed.db_services['pg-main']).toEqual({
      family: 'postgres',
      dialect: 'postgres',
      upstream: '127.0.0.1:5432',
      tls_mode: 'terminate_reissue',
    });
  });

  it('emits all optional flags in snake_case when set', () => {
    const result = serializePolicy({
      dbServices: {
        'aurora': {
          family: 'postgres',
          dialect: 'aurora_postgres',
          upstream: 'aurora.local:5432',
          tlsMode: 'terminate_plaintext_upstream',
          allowFunctionCallProtocol: true,
          allowGssEncryption: false,
          trustedNetwork: true,
        },
      },
    });
    const parsed = yaml.load(result) as any;
    expect(parsed.db_services.aurora.allow_function_call_protocol).toBe(true);
    expect(parsed.db_services.aurora.allow_gss_encryption).toBe(false);
    expect(parsed.db_services.aurora.trusted_network).toBe(true);
  });

  it('omits optional flags when not set', () => {
    const result = serializePolicy({
      dbServices: {
        'minimal': {
          family: 'postgres',
          dialect: 'postgres',
          upstream: 'h:5432',
          tlsMode: 'passthrough',
        },
      },
    });
    const parsed = yaml.load(result) as any;
    expect(parsed.db_services.minimal).not.toHaveProperty('allow_function_call_protocol');
    expect(parsed.db_services.minimal).not.toHaveProperty('allow_gss_encryption');
    expect(parsed.db_services.minimal).not.toHaveProperty('trusted_network');
  });

  it('omits db_services entirely when not set or empty', () => {
    const resultA = serializePolicy({});
    const resultB = serializePolicy({ dbServices: {} });
    expect(yaml.load(resultA) as any).not.toHaveProperty('db_services');
    expect(yaml.load(resultB) as any).not.toHaveProperty('db_services');
  });
});
