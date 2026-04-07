import type { SandboxAdapter, SecureConfig } from '../core/types.js';
import type { ServerConfigOpts } from '../core/config.js';
import type { PolicyDefinition } from '../policies/schema.js';
import { shellEscape, envPrefix } from '../core/shell.js';

const AGENTSH_VERSION = '0.17.0';

/**
 * Wraps a Freestyle VM into a SandboxAdapter.
 *
 * Freestyle provides Firecracker-backed Linux VMs accessed via the
 * `freestyle-sandboxes` SDK. Unlike shell-only providers, Freestyle
 * exposes a typed filesystem API (`vm.fs.*`), so `writeFile`/`readFile`
 * use it directly instead of the base64-over-exec workaround.
 *
 * The `vm` parameter is typed `any` to keep `freestyle-sandboxes` as an
 * optional peer dependency. The adapter expects these methods:
 *   - `vm.exec({command, timeoutMs?}): Promise<{stdout?, stderr?, statusCode?}>`
 *   - `vm.fs.writeTextFile(path, content): Promise<void>`
 *   - `vm.fs.readTextFile(path): Promise<string>`
 *   - `vm.fs.exists(path): Promise<boolean>`
 *   - `vm.stop(): Promise<unknown>`
 *
 * Use `freestyleDefaults()` for security configuration optimized for
 * Freestyle's kernel (no Yama, so seccomp file_monitor is disabled; FUSE
 * in deferred mode with `sudo /bin/chmod 666 /dev/fuse`).
 *
 * @example
 * ```ts
 * import { freestyle as freestyleClient, VmSpec } from 'freestyle-sandboxes';
 * import { secureSandbox } from '@agentsh/secure-sandbox';
 * import { freestyle, freestyleDefaults } from '@agentsh/secure-sandbox/adapters/freestyle';
 *
 * const fs = freestyleClient({ apiKey: process.env.FREESTYLE_API_KEY });
 * const { vm } = await fs.vms.create({ spec: new VmSpec() });
 * const sandbox = await secureSandbox(freestyle(vm), freestyleDefaults());
 * await sandbox.exec('echo hello');
 * await sandbox.stop();
 * ```
 */
export function freestyle(vm: any): SandboxAdapter {
  async function run(command: string, timeoutMs?: number): Promise<{ stdout: string; stderr: string; exitCode: number }> {
    try {
      const result = await vm.exec({ command, timeoutMs });
      return {
        stdout: result?.stdout ?? '',
        stderr: result?.stderr ?? '',
        exitCode: result?.statusCode ?? 0,
      };
    } catch (err: any) {
      return {
        stdout: err?.stdout ?? '',
        stderr: err?.stderr ?? err?.message ?? String(err),
        exitCode: err?.statusCode ?? err?.exitCode ?? 1,
      };
    }
  }

  return {
    async exec(cmd, args, opts) {
      const inner = `${envPrefix(opts?.env)}${opts?.sudo ? 'sudo ' : ''}${shellEscape(cmd, args)}`;
      const wrapped = opts?.cwd
        ? `cd '${opts.cwd.replace(/'/g, "'\\''")}' && ${inner}`
        : inner;
      const command = `sh -c ${shellEscape('', [wrapped])}`;

      if (opts?.detached) {
        const detached = `nohup sh -c ${shellEscape('', [wrapped])} > /dev/null 2>&1 &`;
        run(`sh -c ${shellEscape('', [detached])}`).catch(() => {});
        return { stdout: '', stderr: '', exitCode: 0 };
      }

      return run(command);
    },
    async writeFile(path, content) {
      try {
        if (Buffer.isBuffer(content)) {
          await vm.fs.writeFile(path, content);
        } else {
          await vm.fs.writeTextFile(path, content);
        }
      } catch (err: any) {
        throw new Error(`writeFile failed: ${err?.message ?? err}`);
      }
    },
    async readFile(path) {
      try {
        return await vm.fs.readTextFile(path);
      } catch (err: any) {
        throw new Error(`readFile failed: ${err?.message ?? err}`);
      }
    },
    async stop() {
      await vm.stop();
    },
    async fileExists(path) {
      return await vm.fs.exists(path);
    },
  };
}

/**
 * Returns Freestyle-optimized defaults for SecureConfig.
 *
 * Key characteristics:
 * - allowDegraded: true — Freestyle kernels lack Yama, so seccomp
 *   file_monitor is disabled; agentsh settles into `minimal` security
 *   mode (seccomp wrapper + network proxy + FUSE + cgroups).
 * - FUSE deferred: enabled via `sudo /bin/chmod 666 /dev/fuse` at first
 *   session start (guarded by marker file /tmp/.agentsh-fuse-enabled).
 * - seccomp.fileMonitor disabled: conflicts with FUSE without Yama
 *   (documented in agentsh-freestyle/config.yaml).
 * - DLP with custom patterns for OpenAI / Anthropic / AWS / GitHub /
 *   JWT / Slack tokens.
 * - Workspace at /home/user (matches Freestyle VM default home).
 * - Two-tier resource caps: the outer server sandbox bound is
 *   4 GB RAM / 100% CPU / 256 procs, while the inner per-policy
 *   resourceLimits (added in the policy half of this function) are
 *   2 GB / 50% / 100 PIDs. The outer bound is a safety ceiling; the
 *   inner limits are what agent sessions actually hit.
 *
 * Spread into your secureSandbox() call:
 *
 *   secureSandbox(freestyle(vm), { ...freestyleDefaults(), ...yourOverrides })
 */
export function freestyleDefaults(): Partial<SecureConfig> {
  const serverConfig: Omit<ServerConfigOpts, 'watchtower' | 'realPaths' | 'threatFeeds' | 'packageChecks'> = {
    grpc: { addr: '127.0.0.1:9090' },
    serverTimeouts: { readTimeout: '30s', writeTimeout: '60s', maxRequestSize: '10MB' },
    logging: { level: 'info', format: 'text', output: 'stderr' },
    sessions: {
      baseDir: '/var/lib/agentsh/sessions',
      maxSessions: 100,
      defaultTimeout: '1h',
      idleTimeout: '15m',
      cleanupInterval: '5m',
    },
    audit: { enabled: true, sqlitePath: '/var/lib/agentsh/events.db' },
    sandboxLimits: { maxMemoryMb: 4096, maxCpuPercent: 100, maxProcesses: 256 },
    allowDegraded: true,
    fuse: {
      deferred: true,
      deferredMarkerFile: '/tmp/.agentsh-fuse-enabled',
      deferredEnableCommand: ['sudo', '/bin/chmod', '666', '/dev/fuse'],
    },
    networkIntercept: { interceptMode: 'all', proxyListenAddr: '127.0.0.1:0' },
    seccompDetails: {
      execve: true,
      fileMonitor: { enabled: false, enforceWithoutFuse: false },
    },
    cgroups: { enabled: true },
    unixSockets: { enabled: true },
    envInject: {
      BASH_ENV: '/usr/lib/agentsh/bash_startup.sh',
    },
    proxy: {
      mode: 'embedded',
      port: 0,
      providers: {
        anthropic: 'https://api.anthropic.com',
        openai: 'https://api.openai.com',
      },
    },
    dlp: {
      mode: 'redact',
      patterns: { email: true, phone: true, credit_card: true, ssn: true, api_keys: true },
      customPatterns: [
        { name: 'openai_key', display: 'OPENAI_KEY', regex: 'sk-[a-zA-Z0-9]{48,}' },
        { name: 'anthropic_key', display: 'ANTHROPIC_KEY', regex: 'sk-ant-[a-zA-Z0-9-]{95,}' },
        { name: 'aws_access_key', display: 'AWS_KEY', regex: 'AKIA[0-9A-Z]{16}' },
        { name: 'github_pat', display: 'GITHUB_TOKEN', regex: 'ghp_[a-zA-Z0-9]{36}' },
        { name: 'github_oauth', display: 'GITHUB_OAUTH', regex: 'gho_[a-zA-Z0-9]{36}' },
        { name: 'jwt_token', display: 'JWT', regex: 'eyJ[a-zA-Z0-9_-]*\\.eyJ[a-zA-Z0-9_-]*\\.[a-zA-Z0-9_-]*' },
        { name: 'private_key', display: 'PRIVATE_KEY', regex: '-----BEGIN [A-Z]+ PRIVATE KEY-----' },
        { name: 'slack_token', display: 'SLACK_TOKEN', regex: 'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}' },
      ],
    },
    approvals: { enabled: false },
    metrics: { enabled: true, path: '/metrics' },
    health: { path: '/health', readinessPath: '/ready' },
    development: { disableAuth: true, verboseErrors: false },
  };

  // Policy is added in Task 6. This placeholder lets the function
  // return a valid-looking Partial<SecureConfig> in the meantime.
  const policy: PolicyDefinition = {
    file: [],
    network: [],
    commands: [],
  } as unknown as PolicyDefinition;

  return {
    policy,
    workspace: '/home/user',
    installStrategy: 'download',
    realPaths: true,
    serverConfig,
  };
}

export function configureFreestyleSpec(_spec: any, _opts?: { agentshVersion?: string; policyYaml?: string; configYaml?: string }): any {
  throw new Error('configureFreestyleSpec: not implemented');
}
