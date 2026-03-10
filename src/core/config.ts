import yaml from 'js-yaml';
import type { ThreatFeedsConfig, PackageChecksConfig, ProviderConfig } from './types.js';

export interface ServerConfigOpts {
  watchtower?: string;
  realPaths?: boolean;
  threatFeeds?: false | ThreatFeedsConfig;
  packageChecks?: false | PackageChecksConfig;
}

/**
 * Default threat feeds: URLhaus (malware) + Phishing.Database (phishing).
 * Both are free, open source, and updated frequently.
 */
export const defaultThreatFeeds: ThreatFeedsConfig = {
  action: 'deny',
  feeds: [
    {
      name: 'urlhaus',
      url: 'https://urlhaus.abuse.ch/downloads/hostfile/',
      format: 'hostfile',
      refreshInterval: '6h',
    },
    {
      name: 'phishing',
      url: 'https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt',
      format: 'domain-list',
      refreshInterval: '12h',
    },
  ],
  allowlist: [
    'github.com',
    '*.github.com',
    'registry.npmjs.org',
    'registry.yarnpkg.com',
    'pypi.org',
    'files.pythonhosted.org',
    'crates.io',
    'static.crates.io',
    'index.crates.io',
    'proxy.golang.org',
    'sum.golang.org',
  ],
};

/**
 * Default package check providers: local, osv, depsdev.
 * All are free and require no API key.
 */
export const defaultPackageCheckProviders: Record<string, { enabled: boolean; priority: number }> = {
  local: { enabled: true, priority: 0 },
  osv: { enabled: true, priority: 1 },
  depsdev: { enabled: true, priority: 2 },
};

/**
 * Convert a camelCase ProviderConfig key to snake_case.
 */
function providerConfigToSnakeCase(config: ProviderConfig): Record<string, unknown> {
  const result: Record<string, unknown> = { enabled: config.enabled ?? true };
  if (config.priority !== undefined) result.priority = config.priority;
  if (config.timeout !== undefined) result.timeout = config.timeout;
  if (config.onFailure !== undefined) result.on_failure = config.onFailure;
  if (config.apiKeyEnv !== undefined) result.api_key_env = config.apiKeyEnv;
  if (config.type !== undefined) result.type = config.type;
  if (config.command !== undefined) result.command = config.command;
  if (config.options !== undefined) result.options = config.options;
  return result;
}

export function generateServerConfig(opts: ServerConfigOpts): string {
  const config: Record<string, unknown> = {
    server: {
      http: {
        addr: '127.0.0.1:18080',
      },
    },
    auth: {
      type: 'none',
    },
    policies: {
      system_dir: '/etc/agentsh/system',
      dir: '/etc/agentsh',
      default: 'policy',
    },
    sandbox: {
      enabled: true,
      allow_degraded: true,
      fuse: { enabled: true },
      network: { enabled: true },
      seccomp: { enabled: true },
    },
  };
  if (opts.watchtower) config.watchtower = opts.watchtower;
  if (opts.realPaths) config.sessions = { real_paths: true };

  // Threat feeds: enabled by default, opt-out with `threatFeeds: false`
  const feeds = opts.threatFeeds === false ? undefined : (opts.threatFeeds ?? defaultThreatFeeds);
  if (feeds) {
    config.threat_feeds = {
      enabled: true,
      action: feeds.action ?? 'deny',
      feeds: feeds.feeds.map(f => ({
        name: f.name,
        url: f.url,
        format: f.format,
        refresh_interval: f.refreshInterval ?? '6h',
      })),
      ...(feeds.allowlist?.length ? { allowlist: feeds.allowlist } : {}),
    };
  }

  // Package checks: disabled by default, opt-in with `packageChecks: {}`
  if (opts.packageChecks) {
    const pc = opts.packageChecks;
    const providers: Record<string, Record<string, unknown>> = {};

    // Start with defaults
    for (const [name, def] of Object.entries(defaultPackageCheckProviders)) {
      providers[name] = { ...def };
    }

    // Merge user-provided providers
    if (pc.providers) {
      for (const [name, value] of Object.entries(pc.providers)) {
        if (value === false) {
          providers[name] = { enabled: false };
        } else if (value === true) {
          providers[name] = { ...(providers[name] ?? {}), enabled: true };
        } else {
          // ProviderConfig object — merge with existing default if present
          const base = providers[name] ?? {};
          providers[name] = { ...base, ...providerConfigToSnakeCase(value) };
        }
      }
    }

    config.package_checks = {
      enabled: true,
      scope: pc.scope ?? 'new_packages_only',
      providers,
    };
  }

  return yaml.dump(config, { lineWidth: -1 });
}
