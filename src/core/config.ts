import yaml from 'js-yaml';
import type { ThreatFeedsConfig, PackageChecksConfig, ProviderConfig } from './types.js';

export interface ServerConfigOpts {
  watchtower?: string;
  realPaths?: boolean;
  threatFeeds?: false | ThreatFeedsConfig;
  packageChecks?: false | PackageChecksConfig;
  grpc?: { addr: string };
  serverTimeouts?: { readTimeout?: string; writeTimeout?: string; maxRequestSize?: string };
  logging?: { level?: string; format?: string; output?: string };
  sessions?: { baseDir?: string; maxSessions?: number; defaultTimeout?: string; idleTimeout?: string; cleanupInterval?: string };
  audit?: { enabled?: boolean; sqlitePath?: string };
  sandboxLimits?: { maxMemoryMb?: number; maxCpuPercent?: number; maxProcesses?: number };
  fuse?: { deferred?: boolean };
  networkIntercept?: { interceptMode?: string; proxyListenAddr?: string };
  seccompDetails?: { execve?: boolean; fileMonitor?: { enabled?: boolean; enforceWithoutFuse?: boolean } };
  cgroups?: { enabled?: boolean };
  unixSockets?: { enabled?: boolean };
  proxy?: { mode?: string; port?: number; providers?: Record<string, string> };
  dlp?: { mode?: string; patterns?: Record<string, boolean>; customPatterns?: Array<{ name: string; display: string; regex: string }> };
  policiesOverride?: { dir?: string; defaultPolicy?: string };
  approvals?: { enabled?: boolean; mode?: string; timeout?: string };
  metrics?: { enabled?: boolean; path?: string };
  health?: { path?: string; readinessPath?: string };
  development?: { disableAuth?: boolean; verboseErrors?: boolean };
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

  // ─── Extended config sections ─────────────────────────────────

  // gRPC
  if (opts.grpc) {
    (config.server as any).grpc = { enabled: true, addr: opts.grpc.addr };
  }

  // Server timeouts → merge into server.http
  if (opts.serverTimeouts) {
    const http = (config.server as any).http;
    if (opts.serverTimeouts.readTimeout) http.read_timeout = opts.serverTimeouts.readTimeout;
    if (opts.serverTimeouts.writeTimeout) http.write_timeout = opts.serverTimeouts.writeTimeout;
    if (opts.serverTimeouts.maxRequestSize) http.max_request_size = opts.serverTimeouts.maxRequestSize;
  }

  // Logging
  if (opts.logging) config.logging = { ...opts.logging };

  // Sessions (merge realPaths + extended sessions)
  const sessionsObj: Record<string, unknown> = {};
  if (opts.realPaths) sessionsObj.real_paths = true;
  if (opts.sessions) {
    if (opts.sessions.baseDir) sessionsObj.base_dir = opts.sessions.baseDir;
    if (opts.sessions.maxSessions !== undefined) sessionsObj.max_sessions = opts.sessions.maxSessions;
    if (opts.sessions.defaultTimeout) sessionsObj.default_timeout = opts.sessions.defaultTimeout;
    if (opts.sessions.idleTimeout) sessionsObj.idle_timeout = opts.sessions.idleTimeout;
    if (opts.sessions.cleanupInterval) sessionsObj.cleanup_interval = opts.sessions.cleanupInterval;
  }
  if (Object.keys(sessionsObj).length > 0) config.sessions = sessionsObj;

  // Audit
  if (opts.audit) {
    const auditObj: Record<string, unknown> = {};
    if (opts.audit.enabled !== undefined) auditObj.enabled = opts.audit.enabled;
    if (opts.audit.sqlitePath) auditObj.sqlite_path = opts.audit.sqlitePath;
    config.audit = auditObj;
  }

  // Sandbox limits
  if (opts.sandboxLimits) {
    (config.sandbox as any).limits = {
      ...(opts.sandboxLimits.maxMemoryMb !== undefined && { max_memory_mb: opts.sandboxLimits.maxMemoryMb }),
      ...(opts.sandboxLimits.maxCpuPercent !== undefined && { max_cpu_percent: opts.sandboxLimits.maxCpuPercent }),
      ...(opts.sandboxLimits.maxProcesses !== undefined && { max_processes: opts.sandboxLimits.maxProcesses }),
    };
  }

  // FUSE deferred
  if (opts.fuse?.deferred !== undefined) {
    (config.sandbox as any).fuse.deferred = opts.fuse.deferred;
  }

  // Network intercept
  if (opts.networkIntercept) {
    const net = (config.sandbox as any).network;
    if (opts.networkIntercept.interceptMode) net.intercept_mode = opts.networkIntercept.interceptMode;
    if (opts.networkIntercept.proxyListenAddr) net.proxy_listen_addr = opts.networkIntercept.proxyListenAddr;
  }

  // Seccomp details
  if (opts.seccompDetails) {
    const sec = (config.sandbox as any).seccomp;
    if (opts.seccompDetails.execve !== undefined) sec.execve = opts.seccompDetails.execve;
    if (opts.seccompDetails.fileMonitor) {
      sec.file_monitor = {
        ...(opts.seccompDetails.fileMonitor.enabled !== undefined && { enabled: opts.seccompDetails.fileMonitor.enabled }),
        ...(opts.seccompDetails.fileMonitor.enforceWithoutFuse !== undefined && { enforce_without_fuse: opts.seccompDetails.fileMonitor.enforceWithoutFuse }),
      };
    }
  }

  // Cgroups
  if (opts.cgroups) {
    (config.sandbox as any).cgroups = { ...opts.cgroups };
  }

  // Unix sockets
  if (opts.unixSockets) {
    (config.sandbox as any).unix_sockets = { ...opts.unixSockets };
  }

  // Proxy
  if (opts.proxy) {
    config.proxy = { ...opts.proxy };
  }

  // DLP
  if (opts.dlp) {
    const dlpObj: Record<string, unknown> = {};
    if (opts.dlp.mode) dlpObj.mode = opts.dlp.mode;
    if (opts.dlp.patterns) dlpObj.patterns = opts.dlp.patterns;
    if (opts.dlp.customPatterns) {
      dlpObj.custom_patterns = opts.dlp.customPatterns.map(p => ({
        name: p.name,
        display: p.display,
        regex: p.regex,
      }));
    }
    config.dlp = dlpObj;
  }

  // Policies override
  if (opts.policiesOverride) {
    config.policies = {
      ...(opts.policiesOverride.dir && { dir: opts.policiesOverride.dir }),
      ...(opts.policiesOverride.defaultPolicy && { default: opts.policiesOverride.defaultPolicy }),
    };
  }

  // Approvals
  if (opts.approvals) config.approvals = { ...opts.approvals };

  // Metrics
  if (opts.metrics) config.metrics = { ...opts.metrics };

  // Health
  if (opts.health) {
    const healthObj: Record<string, unknown> = {};
    if (opts.health.path) healthObj.path = opts.health.path;
    if (opts.health.readinessPath) healthObj.readiness_path = opts.health.readinessPath;
    config.health = healthObj;
  }

  // Development
  if (opts.development) {
    const devObj: Record<string, unknown> = {};
    if (opts.development.disableAuth !== undefined) devObj.disable_auth = opts.development.disableAuth;
    if (opts.development.verboseErrors !== undefined) devObj.verbose_errors = opts.development.verboseErrors;
    config.development = devObj;
  }

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
