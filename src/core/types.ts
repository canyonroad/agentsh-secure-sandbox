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
   *   Skips install, shim, policy, config, and server startup.
   *   Only detects security mode, runs health check, and creates session.
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
   * Make redirect rules enforced (deny execution) instead of shadowing
   * to a stub binary.
   * Default: false (shadow mode).
   */
  enforceRedirects?: boolean;

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
}

export interface CreateSandboxConfig extends SecureConfig {
  /** Vercel Sandbox runtime. Default: 'node24'. */
  runtime?: 'node22' | 'node24' | 'python3.13';

  /** Sandbox timeout in milliseconds. Default: 300_000 (5 min). */
  timeout?: number;

  /** Number of vCPUs. Default: 2. */
  vcpus?: 1 | 2 | 4 | 8;

  /** Create from existing snapshot ID (skips binary install). */
  snapshot?: string;
}
