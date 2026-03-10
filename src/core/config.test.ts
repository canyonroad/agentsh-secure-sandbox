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
    expect(parsed.sessions).toBeUndefined();
  });

  it('enables sandbox subsections by default', () => {
    const result = generateServerConfig({});
    const parsed = yaml.load(result) as any;
    expect(parsed.sandbox.enabled).toBe(true);
    expect(parsed.sandbox.fuse.enabled).toBe(true);
    expect(parsed.sandbox.network.enabled).toBe(true);
    expect(parsed.sandbox.seccomp.enabled).toBe(true);
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
    expect(parsed.audit).toEqual({ enabled: true, sqlite_path: '/var/audit.db' });
  });

  it('generates sandbox.limits', () => {
    const result = generateServerConfig({ sandboxLimits: { maxMemoryMb: 512, maxCpuPercent: 80, maxProcesses: 100 } });
    const parsed = yaml.load(result) as any;
    expect(parsed.sandbox.limits).toEqual({ max_memory_mb: 512, max_cpu_percent: 80, max_processes: 100 });
  });

  it('sets fuse.deferred', () => {
    const result = generateServerConfig({ fuse: { deferred: true } });
    const parsed = yaml.load(result) as any;
    expect(parsed.sandbox.fuse.enabled).toBe(true);
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
    expect(parsed.sandbox.seccomp.execve).toBe(true);
    expect(parsed.sandbox.seccomp.file_monitor).toEqual({ enabled: true, enforce_without_fuse: false });
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
    expect(parsed.sandbox.unix_sockets).toBeUndefined();
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
