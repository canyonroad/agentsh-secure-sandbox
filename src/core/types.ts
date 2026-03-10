// ─── Core result types ────────────────────────────────────────

export interface ExecResult {
  stdout: string;
  stderr: string;
  exitCode: number;
}

// ─── Discriminated union result types ─────────────────────────

export type WriteFileResult =
  | { success: true; path: string }
  | { success: false; path: string; error: string };

export type ReadFileResult =
  | { success: true; path: string; content: string }
  | { success: false; path: string; error: string };

// ─── Security & install enums ─────────────────────────────────

export type SecurityMode = 'full' | 'landlock' | 'landlock-only' | 'minimal';

export type InstallStrategy = 'preinstalled' | 'download' | 'upload' | 'running';

// ─── SandboxAdapter interface ─────────────────────────────────

export interface SandboxAdapter {
  /**
   * Execute a command inside the sandbox.
   *
   * During provisioning: used for installing binary, starting server,
   * creating session, health checks.
   *
   * At runtime: used as transport for `agentsh exec $SID -- <command>`.
   */
  exec(
    cmd: string,
    args?: string[],
    opts?: {
      cwd?: string;
      sudo?: boolean;
      /** If true, don't wait for completion (for starting daemons). */
      detached?: boolean;
      /** Environment variables to set for this command. */
      env?: Record<string, string>;
    },
  ): Promise<ExecResult>;

  /**
   * Write a file inside the sandbox.
   * Used during provisioning only: writing policy, writing config,
   * uploading binary (when installStrategy is 'upload').
   * Never called at runtime.
   */
  writeFile(
    path: string,
    content: string | Buffer,
    opts?: { sudo?: boolean },
  ): Promise<void>;

  /**
   * Read a file from the sandbox.
   * Used during provisioning only: health checks, reading session output.
   * Never called at runtime.
   */
  readFile(path: string): Promise<string>;

  /** Stop/destroy the sandbox. Optional. */
  stop?(): Promise<void>;

  /**
   * Check if a file exists. Optional.
   * Used to detect pre-installed agentsh in snapshots.
   * If not implemented, the library uses exec('test -f ...').
   */
  fileExists?(path: string): Promise<boolean>;
}

// ─── SecuredSandbox interface ─────────────────────────────────

export interface SecuredSandbox {
  /**
   * Run a shell command through agentsh.
   *
   * Internally executes:
   *   adapter.exec('agentsh', ['exec', '--output', 'json', sessionId, '--', 'bash', '-c', command])
   *
   * Every subprocess spawned by this command is also policy-enforced
   * via the shell shim and agentsh's process tree tracking.
   */
  exec(
    command: string,
    opts?: {
      cwd?: string;
      /** Timeout in milliseconds. Default: no timeout. */
      timeout?: number;
    },
  ): Promise<ExecResult>;

  /**
   * Write a text file through agentsh.
   * Returns success/failure + path. On deny, returns the policy message
   * instead of throwing.
   */
  writeFile(path: string, content: string): Promise<WriteFileResult>;

  /**
   * Read a text file through agentsh.
   * Returns content on success, error message on deny.
   */
  readFile(path: string): Promise<ReadFileResult>;

  /** Stop the sandbox and clean up all resources. */
  stop(): Promise<void>;

  /** The agentsh session ID (for Watchtower / telemetry). */
  readonly sessionId: string;

  /**
   * The security mode detected by `agentsh detect` during provisioning.
   * 'full' = seccomp + eBPF + FUSE (100% enforcement)
   * 'landlock' = Landlock + FUSE (~85%)
   * 'landlock-only' = Landlock without FUSE (~80%)
   * 'minimal' = capability dropping + shim only (~50%)
   */
  readonly securityMode: SecurityMode;
}

// ─── Configuration types ──────────────────────────────────────

// PolicyDefinition is imported from the policy schema module.
// Using a forward-declared type here to avoid circular dependency.
// The actual PolicyDefinition type is defined in policies/schema.ts.

export interface SecureConfig {
  /**
   * Policy: a PolicyDefinition object or a preset function result.
   * Default: policies.agentDefault()
   */
  policy?: unknown; // PolicyDefinition — typed as unknown until policy module is built

  /** Workspace root inside the sandbox. Default: '/workspace'. */
  workspace?: string;

  /** Watchtower event sink URL. Optional. */
  watchtower?: string;

  /**
   * How to get the agentsh binary into the sandbox.
   * - 'preinstalled': Binary already exists (snapshot or baked image).
   * - 'download': Download from GitHub releases inside the sandbox. Default.
   * - 'upload': Library downloads on host, uploads via adapter.writeFile().
   * - 'running': agentsh is already fully provisioned and running.
   *   Skips install, shim, policy, config, server startup, and security
   *   detection. Defaults securityMode to 'full' (override via securityMode).
   *   Runs health check and reads the existing session from the environment.
   */
  installStrategy?: InstallStrategy;

  /** Override agentsh binary version. Default: pinned per library release. */
  agentshVersion?: string;

  /** Override agentsh binary architecture. Default: auto-detected. */
  agentshArch?: 'linux_amd64' | 'linux_arm64';

  /** Override agentsh binary download URL (for 'download' strategy). */
  agentshBinaryUrl?: string;

  /** Override SHA256 checksum. Use with custom binary URL. */
  agentshChecksum?: string;

  /**
   * Skip SHA256 integrity check. NOT RECOMMENDED.
   * Only use if you are providing your own binary via a trusted channel.
   */
  skipIntegrityCheck?: boolean;

  /**
   * Override the detected security mode. Only used with installStrategy 'running',
   * where `agentsh detect` is skipped (it would conflict with the running server).
   * Default for 'running': 'full'. Ignored for other install strategies.
   */
  securityMode?: SecurityMode;

  /**
   * Minimum acceptable security mode. If `agentsh detect` reports a
   * weaker mode, provisioning fails with ProvisioningError.
   * Default: undefined (accept any mode, log warning if degraded).
   */
  minimumSecurityMode?: SecurityMode;

  /**
   * Use real host paths instead of virtualizing under /workspace.
   * Default: auto-detected. Enabled when FUSE is available (security
   * mode 'full' or 'landlock'), disabled otherwise. Set explicitly
   * to override auto-detection.
   */
  realPaths?: boolean;

  /**
   * W3C traceparent header to propagate into the agentsh session.
   * Format: '00-<trace-id>-<span-id>-<flags>'
   */
  traceParent?: string;

  /**
   * Policy name for session creation. Only used with installStrategy 'running'.
   * Must match a policy file in the server's policy directory.
   * Default: 'policy' (matches the file written by other install strategies).
   */
  policyName?: string;

  /**
   * Existing agentsh session ID. Only used with installStrategy 'running'.
   * If not provided, reads $AGENTSH_SESSION_ID from the sandbox environment.
   * Use this when the sandbox exec API doesn't inherit shell profile env vars.
   */
  sessionId?: string;

  /**
   * Threat intelligence feeds for blocking known-malicious domains.
   * Default: enabled with URLhaus and Phishing.Database feeds.
   * Set to `false` to disable, or provide a custom ThreatFeedsConfig.
   */
  threatFeeds?: false | ThreatFeedsConfig;

  /**
   * Package install security checks.
   * Set to `false` to disable, or provide a PackageChecksConfig.
   */
  packageChecks?: false | PackageChecksConfig;

  /** Extended server config options (gRPC, logging, sessions, audit, DLP, proxy, etc.). */
  serverConfig?: Omit<import('./config.js').ServerConfigOpts, 'watchtower' | 'realPaths' | 'threatFeeds' | 'packageChecks'>;
}

// ─── Threat feeds configuration ──────────────────────────────

export interface ThreatFeed {
  /** Display name for this feed. */
  name: string;
  /** URL to fetch the feed from. */
  url: string;
  /** Feed format: 'hostfile' (hosts-style) or 'domain-list' (one domain per line). */
  format: 'hostfile' | 'domain-list';
  /** How often to refresh the feed. Default: '6h'. */
  refreshInterval?: string;
}

export interface ThreatFeedsConfig {
  /** Action to take when a domain matches a feed. Default: 'deny'. */
  action?: 'deny' | 'audit';
  /** Feed sources. */
  feeds: ThreatFeed[];
  /** Domains to exclude from blocking (e.g. legitimate services that may appear in feeds). */
  allowlist?: string[];
}

// ─── Package checks configuration ───────────────────────────

export interface ProviderConfig {
  /** Whether this provider is enabled. */
  enabled?: boolean;
  /** Priority order (lower = higher priority). */
  priority?: number;
  /** Timeout duration string (e.g. '30s', '2m'). */
  timeout?: string;
  /** Action on provider failure. */
  onFailure?: 'warn' | 'deny' | 'allow' | 'approve';
  /** Environment variable name holding the API key. */
  apiKeyEnv?: string;
  /** Provider type. */
  type?: 'exec';
  /** Command to execute (for 'exec' type providers). */
  command?: string;
  /** Additional provider-specific options. */
  options?: Record<string, unknown>;
}

export interface PackageChecksConfig {
  /** Whether to check only new packages or all installs. */
  scope?: 'new_packages_only' | 'all_installs';
  /** Map of provider name to provider configuration (or boolean shorthand). */
  providers?: Record<string, boolean | ProviderConfig>;
}

export interface LicenseSpdxMatch {
  /** Allowed SPDX license identifiers. */
  allow?: string[];
  /** Denied SPDX license identifiers. */
  deny?: string[];
}

export interface PackageMatch {
  /** Exact package names to match. */
  packages?: string[];
  /** Glob/regex patterns for package names. */
  namePatterns?: string[];
  /** Type of finding to match (e.g. 'malware', 'vulnerability'). */
  findingType?: string;
  /** Severity level to match. */
  severity?: string | string[];
  /** Reasons to match. */
  reasons?: string[];
  /** SPDX license matching criteria. */
  licenseSpdx?: LicenseSpdxMatch;
  /** Package ecosystem (e.g. 'npm', 'pip'). */
  ecosystem?: string;
  /** Additional match options. */
  options?: Record<string, unknown>;
}

export interface PackageRule {
  /** Matching criteria for the rule. */
  match: PackageMatch;
  /** Action to take when the rule matches. */
  action: 'allow' | 'warn' | 'approve' | 'block';
  /** Human-readable reason for the rule. */
  reason?: string;
}
