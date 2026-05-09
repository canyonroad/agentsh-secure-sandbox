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
  audit?: {
    enabled?: boolean;
    sqlitePath?: string;
    batchSize?: number;
    flushInterval?: string;
    channelSize?: number;
    integrity?: {
      enabled?: boolean;
      algorithm?: 'hmac-sha256' | 'hmac-sha512';
      keySource?: 'file' | 'env' | 'aws_kms' | 'azure_keyvault' | 'hashicorp_vault' | 'gcp_kms';
      keyFile?: string;
      keyEnv?: string;
      awsKms?: { keyId: string; region: string; encryptedDekFile?: string };
      azureKeyVault?: { vaultUrl: string; keyName: string; keyVersion?: string };
      hashicorpVault?: {
        address: string;
        authMethod?: string;
        tokenFile?: string;
        kubernetesRole?: string;
        approleId?: string;
        secretId?: string;
        secretPath: string;
        keyField?: string;
      };
      gcpKms?: { keyName: string; encryptedDekFile?: string };
    };
  };
  sandboxLimits?: { maxMemoryMb?: number; maxCpuPercent?: number; maxProcesses?: number };
  allowDegraded?: boolean;
  fuse?: { enabled?: boolean; deferred?: boolean; deferredMarkerFile?: string; deferredEnableCommand?: string[] };
  networkIntercept?: { interceptMode?: string; proxyListenAddr?: string };
  seccompDetails?: {
    mode?: 'enforce' | 'audit' | 'disabled';
    unixSocket?: { enabled?: boolean; action?: 'enforce' | 'audit' };
    execve?: boolean;
    execveDetails?: {
      maxArgc?: number;
      maxArgvBytes?: number;
      onTruncated?: 'deny' | 'allow' | 'approval';
      approvalTimeout?: string;
      approvalTimeoutAction?: 'deny' | 'allow';
      internalBypass?: string[];
    };
    fileMonitor?: { enabled?: boolean; enforceWithoutFuse?: boolean; interceptMetadata?: boolean; openatEmulation?: boolean; blockIoUring?: boolean };
    blockedSocketFamilies?: Array<{
      family: string;
      action?: 'errno' | 'kill' | 'log' | 'log_and_kill';
    }>;
    socketRules?: Array<{
      name: string;
      family: string;
      type?: string;
      protocol?: string;
      action?: 'errno' | 'kill' | 'log' | 'log_and_kill';
    }>;
    syscalls?: {
      defaultAction?: 'allow' | 'block';
      block?: string[];
      allow?: string[];
      onBlock?: 'errno' | 'kill' | 'log' | 'log_and_kill';
    };
    mitigationSets?: string[];
    mitigationDirs?: string[];
  };
  cgroups?: { enabled?: boolean };
  unixSockets?: { enabled?: boolean };
  ptrace?: {
    enabled?: boolean;
    attachMode?: 'children' | 'pid';
    maskTracerPid?: string;
    trace?: {
      execve?: boolean;
      file?: boolean;
      network?: boolean;
      signal?: boolean;
    };
    performance?: {
      seccompPrefilter?: boolean;
      maxTracees?: number;
      maxHoldMs?: number;
      staticAllowFile?: boolean;
      staticAllowNetwork?: boolean;
      argLevelFilter?: boolean;
    };
    onAttachFailure?: 'fail_open' | 'fail_closed';
  };
  envInject?: Record<string, string>;
  proxy?: { mode?: string; port?: number; providers?: Record<string, string> };
  dlp?: { mode?: string; patterns?: Record<string, boolean>; customPatterns?: Array<{ name: string; display: string; regex: string }> };
  policiesOverride?: { dir?: string; defaultPolicy?: string };
  policySigning?: { trustStore?: string; mode?: 'enforce' | 'warn' | 'off' };
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
      allow_degraded: opts.allowDegraded ?? true,
      // FUSE disabled by default: when agentsh server runs as root and exec
      // users are non-root (e.g. E2B, Daytona), the FUSE workspace-mnt is
      // inaccessible to non-root users causing exec to fail with exit code 2.
      // File policy is still enforced via landlock. Enable FUSE
      // explicitly via serverConfig: { fuse: { enabled: true } } if needed.
      fuse: { enabled: false },
      network: { enabled: true },
      // Seccomp NOTIFY disabled by default: many container environments
      // (Daytona, E2B custom images) restrict the seccomp() syscall via their
      // container seccomp profile, causing "install seccomp filter: operation
      // canceled" on every exec. Policy is still enforced via landlock and
      // network rules. When ptrace is enabled, seccomp is also incompatible.
      seccomp: { enabled: false },
      // Unix sockets wrapper disabled alongside seccomp: the wrapper
      // (agentsh-unixwrap) installs seccomp-bpf filters that fail in the same
      // container environments that block seccomp(). In v0.16.9+, leaving this
      // defaulted to true triggers file_monitor enforcement which intercepts
      // ALL file operations — breaking commands unless the policy explicitly
      // allows every system file path.
      unix_sockets: { enabled: false },
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
  const sessionsObj: Record<string, unknown> = {
    // Default sessions to a writable location outside /etc/agentsh (which is
    // locked to 555/444 during provisioning). v0.16.2+ resolves workspace mount
    // symlinks inside the sessions dir, which requires write access.
    base_dir: '/var/lib/agentsh/sessions',
  };
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
    if (opts.audit.sqlitePath) {
      const storageObj: Record<string, unknown> = { sqlite_path: opts.audit.sqlitePath };
      if (opts.audit.batchSize !== undefined) storageObj.batch_size = opts.audit.batchSize;
      if (opts.audit.flushInterval) storageObj.flush_interval = opts.audit.flushInterval;
      if (opts.audit.channelSize !== undefined) storageObj.channel_size = opts.audit.channelSize;
      auditObj.storage = storageObj;
    }
    if (opts.audit.integrity) {
      const integ: Record<string, unknown> = {};
      if (opts.audit.integrity.enabled !== undefined) integ.enabled = opts.audit.integrity.enabled;
      if (opts.audit.integrity.algorithm) integ.algorithm = opts.audit.integrity.algorithm;
      if (opts.audit.integrity.keySource) integ.key_source = opts.audit.integrity.keySource;
      if (opts.audit.integrity.keyFile) integ.key_file = opts.audit.integrity.keyFile;
      if (opts.audit.integrity.keyEnv) integ.key_env = opts.audit.integrity.keyEnv;
      if (opts.audit.integrity.awsKms) {
        integ.aws_kms = {
          key_id: opts.audit.integrity.awsKms.keyId,
          region: opts.audit.integrity.awsKms.region,
          ...(opts.audit.integrity.awsKms.encryptedDekFile && { encrypted_dek_file: opts.audit.integrity.awsKms.encryptedDekFile }),
        };
      }
      if (opts.audit.integrity.azureKeyVault) {
        integ.azure_keyvault = {
          vault_url: opts.audit.integrity.azureKeyVault.vaultUrl,
          key_name: opts.audit.integrity.azureKeyVault.keyName,
          ...(opts.audit.integrity.azureKeyVault.keyVersion && { key_version: opts.audit.integrity.azureKeyVault.keyVersion }),
        };
      }
      if (opts.audit.integrity.hashicorpVault) {
        const hv = opts.audit.integrity.hashicorpVault;
        integ.hashicorp_vault = {
          address: hv.address,
          secret_path: hv.secretPath,
          ...(hv.authMethod && { auth_method: hv.authMethod }),
          ...(hv.tokenFile && { token_file: hv.tokenFile }),
          ...(hv.kubernetesRole && { kubernetes_role: hv.kubernetesRole }),
          ...(hv.approleId && { approle_id: hv.approleId }),
          ...(hv.secretId && { secret_id: hv.secretId }),
          ...(hv.keyField && { key_field: hv.keyField }),
        };
      }
      if (opts.audit.integrity.gcpKms) {
        integ.gcp_kms = {
          key_name: opts.audit.integrity.gcpKms.keyName,
          ...(opts.audit.integrity.gcpKms.encryptedDekFile && { encrypted_dek_file: opts.audit.integrity.gcpKms.encryptedDekFile }),
        };
      }
      auditObj.integrity = integ;
    }
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
  if (opts.fuse) {
    const fuseObj = (config.sandbox as any).fuse;
    if (opts.fuse.enabled !== undefined) fuseObj.enabled = opts.fuse.enabled;
    if (opts.fuse.deferred !== undefined) fuseObj.deferred = opts.fuse.deferred;
    if (opts.fuse.deferredMarkerFile) fuseObj.deferred_marker_file = opts.fuse.deferredMarkerFile;
    if (opts.fuse.deferredEnableCommand) fuseObj.deferred_enable_command = opts.fuse.deferredEnableCommand;
  }

  // Network intercept
  if (opts.networkIntercept) {
    const net = (config.sandbox as any).network;
    if (opts.networkIntercept.interceptMode) net.intercept_mode = opts.networkIntercept.interceptMode;
    if (opts.networkIntercept.proxyListenAddr) net.proxy_listen_addr = opts.networkIntercept.proxyListenAddr;
  }

  // Seccomp details — providing seccompDetails implicitly enables seccomp
  // (unless ptrace is also enabled, since they're mutually exclusive)
  if (opts.seccompDetails) {
    const sec = (config.sandbox as any).seccomp;
    if (!opts.ptrace?.enabled) sec.enabled = true;
    if (opts.seccompDetails.mode !== undefined) sec.mode = opts.seccompDetails.mode;
    if (opts.seccompDetails.unixSocket) {
      sec.unix_socket = {
        ...(opts.seccompDetails.unixSocket.enabled !== undefined && { enabled: opts.seccompDetails.unixSocket.enabled }),
        ...(opts.seccompDetails.unixSocket.action !== undefined && { action: opts.seccompDetails.unixSocket.action }),
      };
    }
    if (opts.seccompDetails.syscalls) {
      sec.syscalls = {
        ...(opts.seccompDetails.syscalls.defaultAction !== undefined && { default_action: opts.seccompDetails.syscalls.defaultAction }),
        ...(opts.seccompDetails.syscalls.block !== undefined && { block: [...opts.seccompDetails.syscalls.block] }),
        ...(opts.seccompDetails.syscalls.allow !== undefined && { allow: [...opts.seccompDetails.syscalls.allow] }),
        ...(opts.seccompDetails.syscalls.onBlock !== undefined && { on_block: opts.seccompDetails.syscalls.onBlock }),
      };
    }
    // agentsh v0.17.0 changed seccomp.execve from a bare bool into an
    // ExecveConfig struct (`enabled` + argv-capture sub-fields). Callers
    // can set `execve: true` for the simple toggle, `execveDetails: {...}`
    // for the sub-fields, or both. When only `execveDetails` is provided
    // we auto-set `enabled: true` — otherwise agentsh would see Go's zero
    // value (false) and ignore the sub-fields silently.
    if (opts.seccompDetails.execve !== undefined || opts.seccompDetails.execveDetails) {
      const ex: Record<string, unknown> = {};
      if (opts.seccompDetails.execve !== undefined) {
        ex.enabled = opts.seccompDetails.execve;
      } else if (opts.seccompDetails.execveDetails) {
        ex.enabled = true;
      }
      const ed = opts.seccompDetails.execveDetails;
      if (ed) {
        if (ed.maxArgc !== undefined) ex.max_argc = ed.maxArgc;
        if (ed.maxArgvBytes !== undefined) ex.max_argv_bytes = ed.maxArgvBytes;
        if (ed.onTruncated !== undefined) ex.on_truncated = ed.onTruncated;
        if (ed.approvalTimeout !== undefined) ex.approval_timeout = ed.approvalTimeout;
        if (ed.approvalTimeoutAction !== undefined) ex.approval_timeout_action = ed.approvalTimeoutAction;
        if (ed.internalBypass !== undefined) ex.internal_bypass = [...ed.internalBypass];
      }
      sec.execve = ex;
    }
    if (opts.seccompDetails.fileMonitor) {
      sec.file_monitor = {
        ...(opts.seccompDetails.fileMonitor.enabled !== undefined && { enabled: opts.seccompDetails.fileMonitor.enabled }),
        ...(opts.seccompDetails.fileMonitor.enforceWithoutFuse !== undefined && { enforce_without_fuse: opts.seccompDetails.fileMonitor.enforceWithoutFuse }),
        ...(opts.seccompDetails.fileMonitor.interceptMetadata !== undefined && { intercept_metadata: opts.seccompDetails.fileMonitor.interceptMetadata }),
        ...(opts.seccompDetails.fileMonitor.openatEmulation !== undefined && { openat_emulation: opts.seccompDetails.fileMonitor.openatEmulation }),
        ...(opts.seccompDetails.fileMonitor.blockIoUring !== undefined && { block_io_uring: opts.seccompDetails.fileMonitor.blockIoUring }),
      };
    }
    if (opts.seccompDetails.blockedSocketFamilies !== undefined) {
      sec.blocked_socket_families = opts.seccompDetails.blockedSocketFamilies.map(e => ({
        family: e.family,
        ...(e.action !== undefined && { action: e.action }),
      }));
    }
    if (opts.seccompDetails.socketRules !== undefined) {
      sec.socket_rules = opts.seccompDetails.socketRules.map(r => ({
        name: r.name,
        family: r.family,
        ...(r.type !== undefined && { type: r.type }),
        ...(r.protocol !== undefined && { protocol: r.protocol }),
        ...(r.action !== undefined && { action: r.action }),
      }));
    }
    if (opts.seccompDetails.mitigationSets !== undefined) {
      sec.mitigation_sets = [...opts.seccompDetails.mitigationSets];
    }
    if (opts.seccompDetails.mitigationDirs !== undefined) {
      sec.mitigation_dirs = [...opts.seccompDetails.mitigationDirs];
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

  // Ptrace
  if (opts.ptrace) {
    const ptraceObj: Record<string, unknown> = {};
    if (opts.ptrace.enabled !== undefined) ptraceObj.enabled = opts.ptrace.enabled;
    if (opts.ptrace.attachMode) ptraceObj.attach_mode = opts.ptrace.attachMode;
    if (opts.ptrace.maskTracerPid) ptraceObj.mask_tracer_pid = opts.ptrace.maskTracerPid;
    if (opts.ptrace.trace) {
      const traceObj: Record<string, unknown> = {};
      if (opts.ptrace.trace.execve !== undefined) traceObj.execve = opts.ptrace.trace.execve;
      if (opts.ptrace.trace.file !== undefined) traceObj.file = opts.ptrace.trace.file;
      if (opts.ptrace.trace.network !== undefined) traceObj.network = opts.ptrace.trace.network;
      if (opts.ptrace.trace.signal !== undefined) traceObj.signal = opts.ptrace.trace.signal;
      ptraceObj.trace = traceObj;
    }
    if (opts.ptrace.performance) {
      const perfObj: Record<string, unknown> = {};
      if (opts.ptrace.performance.seccompPrefilter !== undefined) perfObj.seccomp_prefilter = opts.ptrace.performance.seccompPrefilter;
      if (opts.ptrace.performance.maxTracees !== undefined) perfObj.max_tracees = opts.ptrace.performance.maxTracees;
      if (opts.ptrace.performance.maxHoldMs !== undefined) perfObj.max_hold_ms = opts.ptrace.performance.maxHoldMs;
      if (opts.ptrace.performance.staticAllowFile !== undefined) perfObj.static_allow_file = opts.ptrace.performance.staticAllowFile;
      if (opts.ptrace.performance.staticAllowNetwork !== undefined) perfObj.static_allow_network = opts.ptrace.performance.staticAllowNetwork;
      if (opts.ptrace.performance.argLevelFilter !== undefined) perfObj.arg_level_filter = opts.ptrace.performance.argLevelFilter;
      ptraceObj.performance = perfObj;
    }
    if (opts.ptrace.onAttachFailure) ptraceObj.on_attach_failure = opts.ptrace.onAttachFailure;
    (config.sandbox as any).ptrace = ptraceObj;
  }

  // Environment injection
  if (opts.envInject) {
    (config.sandbox as any).env_inject = { ...opts.envInject };
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

  // Policy signing (v0.16.9+)
  if (opts.policySigning) {
    const policies = (config.policies as Record<string, unknown>) ?? {};
    const signingObj: Record<string, unknown> = {};
    if (opts.policySigning.trustStore) signingObj.trust_store = opts.policySigning.trustStore;
    if (opts.policySigning.mode) signingObj.mode = opts.policySigning.mode;
    policies.signing = signingObj;
    config.policies = policies;
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
