import { describe, it, expect } from 'vitest';
import yaml from 'js-yaml';
import { generateServerConfig, defaultThreatFeeds } from './config.js';

describe('generateServerConfig', () => {
  it('generates valid YAML with policy dirs', () => {
    const result = generateServerConfig({});
    const parsed = yaml.load(result) as any;
    expect(parsed.policies.system_dir).toBe('/etc/agentsh/system');
    expect(parsed.policies.dir).toBe('/etc/agentsh');
    expect(parsed.policies.default).toBe('policy');
  });

  it('does not include workspace in config', () => {
    const result = generateServerConfig({});
    const parsed = yaml.load(result) as any;
    expect(parsed.workspace).toBeUndefined();
  });

  it('includes watchtower when provided', () => {
    const result = generateServerConfig({ watchtower: 'https://watchtower.example.com' });
    const parsed = yaml.load(result) as any;
    expect(parsed.watchtower).toBe('https://watchtower.example.com');
  });

  it('omits watchtower when not provided', () => {
    const result = generateServerConfig({});
    const parsed = yaml.load(result) as any;
    expect(parsed.watchtower).toBeUndefined();
  });

  it('includes realPaths nested under sessions', () => {
    const result = generateServerConfig({ realPaths: true });
    const parsed = yaml.load(result) as any;
    expect(parsed.sessions.real_paths).toBe(true);
  });

  it('omits sessions.real_paths when not set', () => {
    const result = generateServerConfig({});
    const parsed = yaml.load(result) as any;
    expect(parsed.sessions.real_paths).toBeUndefined();
    // base_dir is always set to a writable location
    expect(parsed.sessions.base_dir).toBe('/var/lib/agentsh/sessions');
  });

  it('enables sandbox subsections by default (fuse and seccomp disabled by default)', () => {
    const result = generateServerConfig({});
    const parsed = yaml.load(result) as any;
    expect(parsed.sandbox.enabled).toBe(true);
    // FUSE is disabled by default to avoid workspace-mnt permission issues
    // for non-root exec users (E2B, Daytona). Enable explicitly via fuse opts.
    expect(parsed.sandbox.fuse.enabled).toBe(false);
    expect(parsed.sandbox.network.enabled).toBe(true);
    // Seccomp NOTIFY is disabled by default: many container environments
    // restrict the seccomp() syscall, causing exec failures.
    expect(parsed.sandbox.seccomp.enabled).toBe(false);
  });

  it('includes default threat feeds when not specified', () => {
    const result = generateServerConfig({});
    const parsed = yaml.load(result) as any;
    expect(parsed.threat_feeds.enabled).toBe(true);
    expect(parsed.threat_feeds.action).toBe('deny');
    expect(parsed.threat_feeds.feeds).toHaveLength(2);
    expect(parsed.threat_feeds.feeds[0].name).toBe('urlhaus');
    expect(parsed.threat_feeds.feeds[1].name).toBe('phishing');
    expect(parsed.threat_feeds.allowlist).toContain('registry.npmjs.org');
  });

  it('disables threat feeds when set to false', () => {
    const result = generateServerConfig({ threatFeeds: false });
    const parsed = yaml.load(result) as any;
    expect(parsed.threat_feeds).toBeUndefined();
  });

  it('uses custom threat feeds when provided', () => {
    const result = generateServerConfig({
      threatFeeds: {
        action: 'audit',
        feeds: [{ name: 'custom', url: 'https://example.com/list.txt', format: 'domain-list' }],
      },
    });
    const parsed = yaml.load(result) as any;
    expect(parsed.threat_feeds.action).toBe('audit');
    expect(parsed.threat_feeds.feeds).toHaveLength(1);
    expect(parsed.threat_feeds.feeds[0].name).toBe('custom');
    expect(parsed.threat_feeds.allowlist).toBeUndefined();
  });
});

describe('generateServerConfig — packageChecks', () => {
  it('omits package_checks when not specified (disabled by default)', () => {
    const result = generateServerConfig({ workspace: '/workspace' });
    const parsed = yaml.load(result) as any;
    expect(parsed.package_checks).toBeUndefined();
  });

  it('omits package_checks when set to false', () => {
    const result = generateServerConfig({ workspace: '/workspace', packageChecks: false });
    const parsed = yaml.load(result) as any;
    expect(parsed.package_checks).toBeUndefined();
  });

  it('produces package_checks with defaults when set to empty object', () => {
    const result = generateServerConfig({ workspace: '/workspace', packageChecks: {} });
    const parsed = yaml.load(result) as any;
    expect(parsed.package_checks.enabled).toBe(true);
    expect(parsed.package_checks.scope).toBe('new_packages_only');
    expect(parsed.package_checks.providers.local).toEqual({ enabled: true, priority: 0 });
    expect(parsed.package_checks.providers.osv).toEqual({ enabled: true, priority: 1 });
    expect(parsed.package_checks.providers.depsdev).toEqual({ enabled: true, priority: 2 });
  });

  it('serializes custom scope correctly', () => {
    const result = generateServerConfig({
      workspace: '/workspace',
      packageChecks: { scope: 'all_installs' },
    });
    const parsed = yaml.load(result) as any;
    expect(parsed.package_checks.scope).toBe('all_installs');
  });

  it('adds socket alongside defaults when providers: { socket: true }', () => {
    const result = generateServerConfig({
      workspace: '/workspace',
      packageChecks: { providers: { socket: true } },
    });
    const parsed = yaml.load(result) as any;
    expect(parsed.package_checks.providers.socket).toEqual({ enabled: true });
    // defaults still present
    expect(parsed.package_checks.providers.local).toEqual({ enabled: true, priority: 0 });
    expect(parsed.package_checks.providers.osv).toEqual({ enabled: true, priority: 1 });
    expect(parsed.package_checks.providers.depsdev).toEqual({ enabled: true, priority: 2 });
  });

  it('serializes provider config with snake_case keys', () => {
    const result = generateServerConfig({
      workspace: '/workspace',
      packageChecks: {
        providers: { socket: { apiKeyEnv: 'SOCKET_KEY', onFailure: 'warn' } },
      },
    });
    const parsed = yaml.load(result) as any;
    expect(parsed.package_checks.providers.socket.enabled).toBe(true);
    expect(parsed.package_checks.providers.socket.api_key_env).toBe('SOCKET_KEY');
    expect(parsed.package_checks.providers.socket.on_failure).toBe('warn');
    // camelCase keys should NOT be present
    expect(parsed.package_checks.providers.socket.apiKeyEnv).toBeUndefined();
    expect(parsed.package_checks.providers.socket.onFailure).toBeUndefined();
  });

  it('disables a default provider when set to false', () => {
    const result = generateServerConfig({
      workspace: '/workspace',
      packageChecks: { providers: { osv: false } },
    });
    const parsed = yaml.load(result) as any;
    expect(parsed.package_checks.providers.osv).toEqual({ enabled: false });
    // other defaults still present
    expect(parsed.package_checks.providers.local).toEqual({ enabled: true, priority: 0 });
    expect(parsed.package_checks.providers.depsdev).toEqual({ enabled: true, priority: 2 });
  });

  it('serializes all ProviderConfig fields to snake_case', () => {
    const result = generateServerConfig({
      workspace: '/workspace',
      packageChecks: {
        providers: {
          custom: {
            enabled: true,
            priority: 5,
            timeout: '30s',
            onFailure: 'deny',
            apiKeyEnv: 'CUSTOM_KEY',
            type: 'exec',
            command: '/usr/bin/custom-check',
            options: { verbose: true },
          },
        },
      },
    });
    const parsed = yaml.load(result) as any;
    const custom = parsed.package_checks.providers.custom;
    expect(custom.enabled).toBe(true);
    expect(custom.priority).toBe(5);
    expect(custom.timeout).toBe('30s');
    expect(custom.on_failure).toBe('deny');
    expect(custom.api_key_env).toBe('CUSTOM_KEY');
    expect(custom.type).toBe('exec');
    expect(custom.command).toBe('/usr/bin/custom-check');
    expect(custom.options).toEqual({ verbose: true });
  });

  it('preserves default priority when a default provider is set to true', () => {
    const result = generateServerConfig({
      workspace: '/workspace',
      packageChecks: { providers: { osv: true } },
    });
    const parsed = yaml.load(result) as any;
    expect(parsed.package_checks.providers.osv).toEqual({ enabled: true, priority: 1 });
  });

  it('overrides default provider config when user provides full config', () => {
    const result = generateServerConfig({
      workspace: '/workspace',
      packageChecks: {
        providers: { osv: { priority: 10, timeout: '60s' } },
      },
    });
    const parsed = yaml.load(result) as any;
    expect(parsed.package_checks.providers.osv.enabled).toBe(true);
    expect(parsed.package_checks.providers.osv.priority).toBe(10);
    expect(parsed.package_checks.providers.osv.timeout).toBe('60s');
  });
});

describe('generateServerConfig — extended fields', () => {
  it('generates server.grpc when grpc is set', () => {
    const result = generateServerConfig({ grpc: { addr: '0.0.0.0:50051' } });
    const parsed = yaml.load(result) as any;
    expect(parsed.server.grpc).toEqual({ enabled: true, addr: '0.0.0.0:50051' });
  });

  it('merges server timeouts into server.http', () => {
    const result = generateServerConfig({
      serverTimeouts: { readTimeout: '30s', writeTimeout: '60s', maxRequestSize: '10mb' },
    });
    const parsed = yaml.load(result) as any;
    expect(parsed.server.http.read_timeout).toBe('30s');
    expect(parsed.server.http.write_timeout).toBe('60s');
    expect(parsed.server.http.max_request_size).toBe('10mb');
    expect(parsed.server.http.addr).toBe('127.0.0.1:18080');
  });

  it('generates logging section', () => {
    const result = generateServerConfig({ logging: { level: 'debug', format: 'json', output: 'stdout' } });
    const parsed = yaml.load(result) as any;
    expect(parsed.logging).toEqual({ level: 'debug', format: 'json', output: 'stdout' });
  });

  it('merges sessions with real_paths', () => {
    const result = generateServerConfig({
      realPaths: true,
      sessions: { baseDir: '/var/sessions', maxSessions: 100, defaultTimeout: '30m', idleTimeout: '10m', cleanupInterval: '5m' },
    });
    const parsed = yaml.load(result) as any;
    expect(parsed.sessions.real_paths).toBe(true);
    expect(parsed.sessions.base_dir).toBe('/var/sessions');
    expect(parsed.sessions.max_sessions).toBe(100);
    expect(parsed.sessions.default_timeout).toBe('30m');
    expect(parsed.sessions.idle_timeout).toBe('10m');
    expect(parsed.sessions.cleanup_interval).toBe('5m');
  });

  it('generates audit section', () => {
    const result = generateServerConfig({ audit: { enabled: true, sqlitePath: '/var/audit.db' } });
    const parsed = yaml.load(result) as any;
    expect(parsed.audit).toEqual({ enabled: true, storage: { sqlite_path: '/var/audit.db' } });
  });

  it('generates sandbox.limits', () => {
    const result = generateServerConfig({ sandboxLimits: { maxMemoryMb: 512, maxCpuPercent: 80, maxProcesses: 100 } });
    const parsed = yaml.load(result) as any;
    expect(parsed.sandbox.limits).toEqual({ max_memory_mb: 512, max_cpu_percent: 80, max_processes: 100 });
  });

  it('sets fuse.deferred (also enables fuse)', () => {
    const result = generateServerConfig({ fuse: { deferred: true } });
    const parsed = yaml.load(result) as any;
    // deferred implies fuse is needed; config.ts merges into the fuse object
    expect(parsed.sandbox.fuse.deferred).toBe(true);
  });

  it('generates network intercept config', () => {
    const result = generateServerConfig({ networkIntercept: { interceptMode: 'tproxy', proxyListenAddr: '127.0.0.1:8888' } });
    const parsed = yaml.load(result) as any;
    expect(parsed.sandbox.network.enabled).toBe(true);
    expect(parsed.sandbox.network.intercept_mode).toBe('tproxy');
    expect(parsed.sandbox.network.proxy_listen_addr).toBe('127.0.0.1:8888');
  });

  it('generates seccomp details with file_monitor', () => {
    const result = generateServerConfig({
      seccompDetails: { execve: true, fileMonitor: { enabled: true, enforceWithoutFuse: false } },
    });
    const parsed = yaml.load(result) as any;
    expect(parsed.sandbox.seccomp.enabled).toBe(true);
    // agentsh v0.17.0+: seccomp.execve is an ExecveConfig struct, not a bool
    expect(parsed.sandbox.seccomp.execve).toEqual({ enabled: true });
    expect(parsed.sandbox.seccomp.file_monitor).toEqual({ enabled: true, enforce_without_fuse: false });
  });

  it('emits blocked_socket_families: [] for explicit opt-out', () => {
    const result = generateServerConfig({
      seccompDetails: { blockedSocketFamilies: [] },
    });
    const parsed = yaml.load(result) as any;
    expect(parsed.sandbox.seccomp.enabled).toBe(true);
    expect(parsed.sandbox.seccomp.blocked_socket_families).toEqual([]);
    expect(Array.isArray(parsed.sandbox.seccomp.blocked_socket_families)).toBe(true);
  });

  it('emits populated blocked_socket_families with optional action per entry', () => {
    const result = generateServerConfig({
      seccompDetails: {
        blockedSocketFamilies: [
          { family: 'AF_VSOCK', action: 'log_and_kill' },
          { family: 'AF_ALG' },
          { family: '38', action: 'errno' },
        ],
      },
    });
    const parsed = yaml.load(result) as any;
    expect(parsed.sandbox.seccomp.blocked_socket_families).toEqual([
      { family: 'AF_VSOCK', action: 'log_and_kill' },
      { family: 'AF_ALG' },
      { family: '38', action: 'errno' },
    ]);
  });

  it('omits blocked_socket_families when field is unset (lets agentsh apply defaults)', () => {
    const result = generateServerConfig({
      seccompDetails: { execve: true },
    });
    const parsed = yaml.load(result) as any;
    expect(parsed.sandbox.seccomp.blocked_socket_families).toBeUndefined();
  });

  it('blockedSocketFamilies alone implicitly enables seccomp', () => {
    const result = generateServerConfig({
      seccompDetails: {
        blockedSocketFamilies: [{ family: 'AF_VSOCK' }],
      },
    });
    const parsed = yaml.load(result) as any;
    expect(parsed.sandbox.seccomp.enabled).toBe(true);
    expect(parsed.sandbox.seccomp.blocked_socket_families).toEqual([{ family: 'AF_VSOCK' }]);
  });

  it('emits socket_rules with all optional fields when set', () => {
    const result = generateServerConfig({
      seccompDetails: {
        socketRules: [
          { name: 'block-rxrpc', family: 'AF_RXRPC', action: 'log_and_kill' },
          { name: 'block-xfrm', family: 'AF_NETLINK', protocol: 'NETLINK_XFRM', action: 'log_and_kill' },
          { name: 'block-raw-icmp', family: 'AF_INET', type: 'SOCK_RAW' },
        ],
      },
    });
    const parsed = yaml.load(result) as any;
    expect(parsed.sandbox.seccomp.enabled).toBe(true);
    expect(parsed.sandbox.seccomp.socket_rules).toEqual([
      { name: 'block-rxrpc', family: 'AF_RXRPC', action: 'log_and_kill' },
      { name: 'block-xfrm', family: 'AF_NETLINK', protocol: 'NETLINK_XFRM', action: 'log_and_kill' },
      { name: 'block-raw-icmp', family: 'AF_INET', type: 'SOCK_RAW' },
    ]);
  });

  it('omits socket_rules when unset', () => {
    const result = generateServerConfig({ seccompDetails: { execve: true } });
    const parsed = yaml.load(result) as any;
    expect(parsed.sandbox.seccomp.socket_rules).toBeUndefined();
  });

  it('socketRules alone implicitly enables seccomp', () => {
    const result = generateServerConfig({
      seccompDetails: {
        socketRules: [{ name: 'r1', family: 'AF_VSOCK' }],
      },
    });
    const parsed = yaml.load(result) as any;
    expect(parsed.sandbox.seccomp.enabled).toBe(true);
  });

  it('ptrace precedence: seccomp stays disabled even with blockedSocketFamilies set', () => {
    const result = generateServerConfig({
      ptrace: { enabled: true },
      seccompDetails: {
        blockedSocketFamilies: [{ family: 'AF_VSOCK', action: 'log' }],
      },
    });
    const parsed = yaml.load(result) as any;
    expect(parsed.sandbox.seccomp.enabled).toBe(false);
    expect(parsed.sandbox.seccomp.blocked_socket_families).toEqual([
      { family: 'AF_VSOCK', action: 'log' },
    ]);
  });

  it('generates cgroups section', () => {
    const result = generateServerConfig({ cgroups: { enabled: true } });
    const parsed = yaml.load(result) as any;
    expect(parsed.sandbox.cgroups).toEqual({ enabled: true });
  });

  it('generates unix_sockets section', () => {
    const result = generateServerConfig({ unixSockets: { enabled: true } });
    const parsed = yaml.load(result) as any;
    expect(parsed.sandbox.unix_sockets).toEqual({ enabled: true });
  });

  it('generates proxy section', () => {
    const result = generateServerConfig({ proxy: { mode: 'mitm', port: 8080, providers: { openai: 'https://api.openai.com' } } });
    const parsed = yaml.load(result) as any;
    expect(parsed.proxy).toEqual({ mode: 'mitm', port: 8080, providers: { openai: 'https://api.openai.com' } });
  });

  it('generates DLP section with custom_patterns', () => {
    const result = generateServerConfig({
      dlp: {
        mode: 'redact',
        patterns: { credit_card: true, ssn: false },
        customPatterns: [{ name: 'api_key', display: 'API Key', regex: 'sk-[a-zA-Z0-9]{32}' }],
      },
    });
    const parsed = yaml.load(result) as any;
    expect(parsed.dlp.mode).toBe('redact');
    expect(parsed.dlp.patterns).toEqual({ credit_card: true, ssn: false });
    expect(parsed.dlp.custom_patterns).toEqual([{ name: 'api_key', display: 'API Key', regex: 'sk-[a-zA-Z0-9]{32}' }]);
  });

  it('overrides policies section when policiesOverride is set', () => {
    const result = generateServerConfig({ policiesOverride: { dir: '/custom/policies', defaultPolicy: 'strict' } });
    const parsed = yaml.load(result) as any;
    expect(parsed.policies).toEqual({ dir: '/custom/policies', default: 'strict' });
    expect(parsed.policies.system_dir).toBeUndefined();
  });

  it('generates approvals section', () => {
    const result = generateServerConfig({ approvals: { enabled: true, mode: 'human', timeout: '5m' } });
    const parsed = yaml.load(result) as any;
    expect(parsed.approvals).toEqual({ enabled: true, mode: 'human', timeout: '5m' });
  });

  it('generates metrics section', () => {
    const result = generateServerConfig({ metrics: { enabled: true, path: '/metrics' } });
    const parsed = yaml.load(result) as any;
    expect(parsed.metrics).toEqual({ enabled: true, path: '/metrics' });
  });

  it('generates health section with readiness_path', () => {
    const result = generateServerConfig({ health: { path: '/healthz', readinessPath: '/readyz' } });
    const parsed = yaml.load(result) as any;
    expect(parsed.health).toEqual({ path: '/healthz', readiness_path: '/readyz' });
  });

  it('generates development section', () => {
    const result = generateServerConfig({ development: { disableAuth: true, verboseErrors: true } });
    const parsed = yaml.load(result) as any;
    expect(parsed.development).toEqual({ disable_auth: true, verbose_errors: true });
  });

  it('omits all extended fields when not set', () => {
    const result = generateServerConfig({});
    const parsed = yaml.load(result) as any;
    expect(parsed.server.grpc).toBeUndefined();
    expect(parsed.logging).toBeUndefined();
    expect(parsed.audit).toBeUndefined();
    expect(parsed.proxy).toBeUndefined();
    expect(parsed.dlp).toBeUndefined();
    expect(parsed.approvals).toBeUndefined();
    expect(parsed.metrics).toBeUndefined();
    expect(parsed.health).toBeUndefined();
    expect(parsed.development).toBeUndefined();
    expect(parsed.sandbox.limits).toBeUndefined();
    expect(parsed.sandbox.cgroups).toBeUndefined();
    expect(parsed.sandbox.unix_sockets).toEqual({ enabled: false });
    expect(parsed.sandbox.ptrace).toBeUndefined();
    expect(parsed.sandbox.env_inject).toBeUndefined();
  });

  it('generates ptrace section with all fields', () => {
    const result = generateServerConfig({
      ptrace: {
        enabled: true,
        attachMode: 'children',
        maskTracerPid: 'off',
        trace: { execve: true, file: true, network: true, signal: true },
        performance: { seccompPrefilter: false, maxTracees: 500, maxHoldMs: 5000 },
        onAttachFailure: 'fail_open',
      },
    });
    const parsed = yaml.load(result) as any;
    expect(parsed.sandbox.ptrace.enabled).toBe(true);
    expect(parsed.sandbox.ptrace.attach_mode).toBe('children');
    expect(parsed.sandbox.ptrace.mask_tracer_pid).toBe('off');
    expect(parsed.sandbox.ptrace.trace).toEqual({ execve: true, file: true, network: true, signal: true });
    expect(parsed.sandbox.ptrace.performance).toEqual({ seccomp_prefilter: false, max_tracees: 500, max_hold_ms: 5000 });
    expect(parsed.sandbox.ptrace.on_attach_failure).toBe('fail_open');
    // seccomp should be auto-disabled when ptrace is enabled
    expect(parsed.sandbox.seccomp.enabled).toBe(false);
  });

  it('generates ptrace with partial fields', () => {
    const result = generateServerConfig({
      ptrace: { enabled: true, trace: { execve: true } },
    });
    const parsed = yaml.load(result) as any;
    expect(parsed.sandbox.ptrace.enabled).toBe(true);
    expect(parsed.sandbox.ptrace.trace).toEqual({ execve: true });
    expect(parsed.sandbox.ptrace.attach_mode).toBeUndefined();
  });

  it('generates env_inject section', () => {
    const result = generateServerConfig({
      envInject: { BASH_ENV: '/usr/lib/agentsh/bash_startup.sh' },
    });
    const parsed = yaml.load(result) as any;
    expect(parsed.sandbox.env_inject).toEqual({ BASH_ENV: '/usr/lib/agentsh/bash_startup.sh' });
  });

  it('defaults allow_degraded to true', () => {
    const result = generateServerConfig({});
    const parsed = yaml.load(result) as any;
    expect(parsed.sandbox.allow_degraded).toBe(true);
  });

  it('respects explicit allowDegraded: false', () => {
    const result = generateServerConfig({ allowDegraded: false });
    const parsed = yaml.load(result) as any;
    expect(parsed.sandbox.allow_degraded).toBe(false);
  });

  it('generates fuse deferred_marker_file and deferred_enable_command', () => {
    const result = generateServerConfig({
      fuse: {
        deferred: true,
        deferredMarkerFile: '/tmp/.agentsh-fuse-enabled',
        deferredEnableCommand: ['/bin/chmod', '666', '/dev/fuse'],
      },
    });
    const parsed = yaml.load(result) as any;
    expect(parsed.sandbox.fuse.deferred).toBe(true);
    expect(parsed.sandbox.fuse.deferred_marker_file).toBe('/tmp/.agentsh-fuse-enabled');
    expect(parsed.sandbox.fuse.deferred_enable_command).toEqual(['/bin/chmod', '666', '/dev/fuse']);
  });

  it('sets fuse.enabled when explicitly set to true', () => {
    const result = generateServerConfig({ fuse: { enabled: true } });
    const parsed = yaml.load(result) as any;
    expect(parsed.sandbox.fuse.enabled).toBe(true);
  });

  it('keeps fuse.enabled false by default even when other fuse opts are set', () => {
    const result = generateServerConfig({ fuse: { deferred: true } });
    const parsed = yaml.load(result) as any;
    expect(parsed.sandbox.fuse.enabled).toBe(false);
    expect(parsed.sandbox.fuse.deferred).toBe(true);
  });

  it('generates audit.integrity with file key source', () => {
    const result = generateServerConfig({
      audit: {
        enabled: true,
        sqlitePath: '/var/audit.db',
        integrity: {
          enabled: true,
          algorithm: 'hmac-sha256',
          keySource: 'file',
          keyFile: '/etc/agentsh/hmac.key',
        },
      },
    });
    const parsed = yaml.load(result) as any;
    expect(parsed.audit.enabled).toBe(true);
    expect(parsed.audit.integrity.enabled).toBe(true);
    expect(parsed.audit.integrity.algorithm).toBe('hmac-sha256');
    expect(parsed.audit.integrity.key_source).toBe('file');
    expect(parsed.audit.integrity.key_file).toBe('/etc/agentsh/hmac.key');
  });

  it('generates audit.integrity with env key source', () => {
    const result = generateServerConfig({
      audit: {
        integrity: {
          enabled: true,
          algorithm: 'hmac-sha512',
          keySource: 'env',
          keyEnv: 'HMAC_KEY',
        },
      },
    });
    const parsed = yaml.load(result) as any;
    expect(parsed.audit.integrity.algorithm).toBe('hmac-sha512');
    expect(parsed.audit.integrity.key_source).toBe('env');
    expect(parsed.audit.integrity.key_env).toBe('HMAC_KEY');
  });

  it('generates audit.integrity with aws_kms key source', () => {
    const result = generateServerConfig({
      audit: {
        integrity: {
          enabled: true,
          keySource: 'aws_kms',
          awsKms: { keyId: 'alias/my-key', region: 'us-east-1', encryptedDekFile: '/var/lib/agentsh/dek.enc' },
        },
      },
    });
    const parsed = yaml.load(result) as any;
    expect(parsed.audit.integrity.key_source).toBe('aws_kms');
    expect(parsed.audit.integrity.aws_kms).toEqual({
      key_id: 'alias/my-key',
      region: 'us-east-1',
      encrypted_dek_file: '/var/lib/agentsh/dek.enc',
    });
  });

  it('generates audit.integrity with azure_keyvault key source', () => {
    const result = generateServerConfig({
      audit: {
        integrity: {
          enabled: true,
          keySource: 'azure_keyvault',
          azureKeyVault: { vaultUrl: 'https://myvault.vault.azure.net', keyName: 'hmac-key', keyVersion: 'v1' },
        },
      },
    });
    const parsed = yaml.load(result) as any;
    expect(parsed.audit.integrity.key_source).toBe('azure_keyvault');
    expect(parsed.audit.integrity.azure_keyvault).toEqual({
      vault_url: 'https://myvault.vault.azure.net',
      key_name: 'hmac-key',
      key_version: 'v1',
    });
  });

  it('generates audit.integrity with hashicorp_vault key source', () => {
    const result = generateServerConfig({
      audit: {
        integrity: {
          enabled: true,
          keySource: 'hashicorp_vault',
          hashicorpVault: {
            address: 'https://vault.internal',
            authMethod: 'kubernetes',
            kubernetesRole: 'agentsh',
            secretPath: 'secret/data/agentsh/audit-key',
            keyField: 'key',
          },
        },
      },
    });
    const parsed = yaml.load(result) as any;
    expect(parsed.audit.integrity.key_source).toBe('hashicorp_vault');
    expect(parsed.audit.integrity.hashicorp_vault).toEqual({
      address: 'https://vault.internal',
      auth_method: 'kubernetes',
      kubernetes_role: 'agentsh',
      secret_path: 'secret/data/agentsh/audit-key',
      key_field: 'key',
    });
  });

  it('generates audit.integrity with gcp_kms key source', () => {
    const result = generateServerConfig({
      audit: {
        integrity: {
          enabled: true,
          keySource: 'gcp_kms',
          gcpKms: {
            keyName: 'projects/my-project/locations/us-east1/keyRings/agentsh/cryptoKeys/audit',
            encryptedDekFile: '/var/lib/agentsh/dek.enc',
          },
        },
      },
    });
    const parsed = yaml.load(result) as any;
    expect(parsed.audit.integrity.key_source).toBe('gcp_kms');
    expect(parsed.audit.integrity.gcp_kms).toEqual({
      key_name: 'projects/my-project/locations/us-east1/keyRings/agentsh/cryptoKeys/audit',
      encrypted_dek_file: '/var/lib/agentsh/dek.enc',
    });
  });

  it('omits audit.integrity when not set', () => {
    const result = generateServerConfig({ audit: { enabled: true } });
    const parsed = yaml.load(result) as any;
    expect(parsed.audit.integrity).toBeUndefined();
  });

  it('omits optional integrity fields when not provided', () => {
    const result = generateServerConfig({
      audit: {
        integrity: {
          enabled: true,
          keySource: 'aws_kms',
          awsKms: { keyId: 'alias/my-key', region: 'us-east-1' },
        },
      },
    });
    const parsed = yaml.load(result) as any;
    expect(parsed.audit.integrity.aws_kms.encrypted_dek_file).toBeUndefined();
  });
});

describe('defaultThreatFeeds', () => {
  it('has urlhaus and phishing feeds', () => {
    expect(defaultThreatFeeds.feeds).toHaveLength(2);
    expect(defaultThreatFeeds.feeds[0].name).toBe('urlhaus');
    expect(defaultThreatFeeds.feeds[0].url).toContain('abuse.ch');
    expect(defaultThreatFeeds.feeds[1].name).toBe('phishing');
    expect(defaultThreatFeeds.feeds[1].url).toContain('Phishing.Database');
  });

  it('has an allowlist with package registries', () => {
    expect(defaultThreatFeeds.allowlist).toContain('registry.npmjs.org');
    expect(defaultThreatFeeds.allowlist).toContain('pypi.org');
    expect(defaultThreatFeeds.allowlist).toContain('github.com');
  });
});
