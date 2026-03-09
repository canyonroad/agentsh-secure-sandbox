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
