import yaml from 'js-yaml';
import type { ThreatFeedsConfig } from './types.js';

export interface ServerConfigOpts {
  watchtower?: string;
  realPaths?: boolean;
  threatFeeds?: false | ThreatFeedsConfig;
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

  return yaml.dump(config, { lineWidth: -1 });
}
