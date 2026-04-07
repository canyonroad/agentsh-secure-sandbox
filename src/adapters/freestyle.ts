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

  // Policy translated from agentsh-freestyle/default.yaml.
  // `approve` decisions on files/commands become `deny` (TS schema only
  // models `approve` for package rules, and embedded adapters have no
  // approval callback loop wired up).
  // First-match-wins: order matters.
  const policy: PolicyDefinition = {
    file: [
      // --- Deny privilege escalation binaries ---
      { deny: [
        '/usr/bin/sudo', '/usr/bin/su', '/usr/bin/pkexec', '/usr/bin/doas',
        '/bin/su', '/usr/sbin/chroot', '/usr/bin/nsenter', '/usr/bin/unshare',
      ] },

      // --- Deny Freestyle infrastructure ---
      { deny: [
        '/usr/bin/envd',
        '/usr/bin/socat',
        '/etc/systemd/**',
        '/run/systemd/**',
      ] },

      // --- Deny credentials (approve → deny) ---
      { deny: ['/home/user/.ssh/**', '/root/.ssh/**'] },
      { deny: ['/home/user/.aws/**', '/root/.aws/**'] },
      { deny: [
        '/home/user/.gcloud/**', '/home/user/.azure/**',
        '/home/user/.config/gcloud/**', '/home/user/.kube/**',
        '/root/.gcloud/**', '/root/.azure/**',
        '/root/.config/gcloud/**', '/root/.kube/**',
      ] },
      { deny: ['**/.env', '**/.env.*'] },
      { deny: ['/home/user/.git-credentials', '/root/.git-credentials', '**/.netrc'] },

      // --- Workspace: read/open/stat/list, then write/create/mkdir/chmod/rename ---
      { allow: ['/home/user', '/home/user/**', '/workspace', '/workspace/**'],
        ops: ['read', 'open', 'stat', 'list', 'readlink'] },
      { allow: ['/home/user', '/home/user/**', '/workspace', '/workspace/**'],
        ops: ['write', 'create', 'mkdir', 'chmod', 'rename'] },
      { softDelete: ['/home/user', '/home/user/**', '/workspace', '/workspace/**'] },

      // --- Temp directories (full access) ---
      { allow: ['/tmp/**', '/var/tmp/**'] },

      // --- System paths (read-only) ---
      { allow: ['/usr/**', '/lib/**', '/lib64/**', '/bin/**', '/sbin/**'],
        ops: ['read', 'open', 'stat', 'list', 'readlink'] },

      // --- Essential device nodes ---
      { allow: [
        '/dev/null', '/dev/zero', '/dev/urandom', '/dev/random',
        '/dev/stdin', '/dev/stdout', '/dev/stderr',
        '/dev/fd/**', '/dev/pts/**', '/dev/tty',
      ], ops: ['read', 'write', 'open', 'stat'] },

      // --- Package caches (read-only) ---
      { allow: [
        '/home/user/.npm/**', '/home/user/.cache/**', '/home/user/.cargo/**',
        '/root/.npm/**', '/root/.cache/**', '/root/.cargo/**',
      ], ops: ['read', 'open', 'stat', 'list'] },

      // --- Sensitive /etc files (deny before /etc read allow) ---
      { deny: ['/etc/shadow', '/etc/gshadow', '/etc/sudoers', '/etc/sudoers.d/**'] },

      // --- /etc minimal read ---
      { allow: [
        '/etc/hosts', '/etc/resolv.conf',
        '/etc/ssl/certs/**', '/etc/ca-certificates/**',
        '/etc/localtime', '/etc/timezone',
        '/etc/ld.so.cache', '/etc/ld.so.preload', '/etc/ld.so.nohwcap',
        '/etc/nsswitch.conf', '/etc/passwd', '/etc/group',
        '/etc/fuse.conf',
      ], ops: ['read', 'open', 'stat', 'readlink'] },

      // --- /proc/self for process introspection ---
      { allow: ['/proc/self/**', '/proc/thread-self/**'],
        ops: ['read', 'open', 'stat', 'list', 'readlink'] },

      // --- agentsh runtime ---
      { allow: ['/var/lib/agentsh/**', '/var/log/agentsh/**'],
        ops: ['read', 'write', 'open', 'stat', 'list', 'readlink'] },

      // --- Block /proc and /sys (catch-all, before default deny) ---
      { deny: ['/proc/**', '/sys/**'] },

      // --- Default deny ---
      { deny: '**' },
    ],
    network: [
      // Localhost (agentsh server + embedded LLM proxy)
      { allowCidrs: ['127.0.0.1/32', '::1/128'] },
      // Package registries
      { allow: ['registry.npmjs.org'], ports: [443] },
      { allow: ['pypi.org', 'files.pythonhosted.org'], ports: [443] },
      { allow: ['crates.io', 'static.crates.io'], ports: [443] },
      { allow: ['proxy.golang.org', 'sum.golang.org'], ports: [443] },
      // Block cloud metadata (SSRF protection)
      { denyCidrs: ['169.254.169.254/32', '100.100.100.200/32'] },
      // Block private/internal networks
      { denyCidrs: ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '169.254.0.0/16'] },
      // Block Freestyle internal events service (TEST-NET-1 range per reference config)
      { denyCidrs: ['192.0.2.0/24'] },
      // Block example malicious domains (kept from reference as test fixture)
      { deny: ['evil.com', '*.evil.com'] },
      // Default deny
      { deny: '*' },
    ],
    commands: [
      // Network tools (network rules enforce domain policy)
      { allow: ['curl', 'wget'] },
      // Safe commands
      {
        allow: [
          'bash', 'sh', '/bin/bash', '/bin/sh', '/usr/bin/bash', '/usr/bin/sh',
          'ls', 'cat', 'head', 'tail', 'grep', 'find', 'wc', 'sort', 'uniq',
          'diff', 'pwd', 'echo', 'date', 'which',
          'env', 'printenv', 'true', 'false', 'test', '[',
          'expr', 'seq', 'sh.real', 'bash.real',
        ],
      },
      // Note: the reference YAML (agentsh-freestyle/default.yaml) applies
      // an "approve" decision to install subcommands (`npm/pip/pip3/cargo`
      // with args_patterns `^install.*` and `^add.*`). The TS
      // CommandRuleSchema is a union of {allow}/{deny}/{redirect,to} and
      // does not support args_patterns, so that rule cannot be expressed
      // here. Dev tools stay allowed at the command layer; the real
      // enforcement for untrusted install flows is (a) the network rules
      // (only the package registries are reachable) and (b) embedded
      // adapters have approvals disabled anyway. Consumers who need
      // per-subcommand approval should bypass freestyleDefaults() and
      // load the raw YAML via agentsh's own policy loader.
      // Dev tools
      {
        allow: [
          'git', 'node', 'npm', 'python', 'python3', 'pip', 'pip3',
          'cargo', 'go', 'make',
        ],
      },
      // Deny raw network tools (reverse-shell prevention)
      { deny: ['nc', 'netcat', 'ncat', 'socat', 'telnet', 'ssh', 'scp', 'rsync'] },
      // Deny system administration
      {
        deny: [
          'shutdown', 'reboot', 'systemctl', 'service',
          'mount', 'umount', 'dd', 'fdisk', 'mkfs',
          'kill', 'killall', 'pkill',
        ],
      },
      // Deny privilege escalation
      { deny: ['sudo', 'su', 'doas', 'chroot', 'nsenter', 'unshare'] },
      // Deny Freestyle infrastructure interference
      { deny: ['socat', 'envd', 'iptables', 'ip6tables', 'nft', 'tc', 'ip'] },
      // Allow all other (file + network rules are the real enforcement)
      { allow: '*' },
    ],
    envPolicy: {
      allow: [
        'PATH', 'HOME', 'USER', 'SHELL', 'LANG', 'LANG_*', 'LC_*',
        'TERM', 'TERM_*', 'TZ', 'PWD', 'OLDPWD', 'SHLVL', '_',
        'NODE_ENV', 'NODE_PATH', 'NPM_*',
        'PYTHONPATH', 'VIRTUAL_ENV', 'PIP_*',
        'GIT_*',
        'AGENTSH_*',
        'HTTP_PROXY', 'HTTPS_PROXY', 'http_proxy', 'https_proxy', 'NO_PROXY', 'no_proxy',
      ],
      deny: [
        'AWS_*', 'AZURE_*', 'GCP_*', 'GOOGLE_*',
        'OPENAI_API_KEY', 'ANTHROPIC_API_KEY',
        'DATABASE_URL', 'DB_*',
        'SECRET_*', 'PASSWORD*', 'PRIVATE_*', 'API_KEY*', 'TOKEN*',
      ],
      blockIteration: true,
      maxBytes: 65536,
      maxKeys: 100,
    },
    signalRules: [
      { name: 'allow-self', signals: ['@all'], target: { type: 'self' }, decision: 'allow' },
      { name: 'allow-children', signals: ['@all'], target: { type: 'children' }, decision: 'allow' },
      { name: 'allow-session', signals: ['SIGTERM', 'SIGINT', 'SIGHUP', 'SIGUSR1', 'SIGUSR2'], target: { type: 'session' }, decision: 'allow' },
      { name: 'audit-parent', signals: ['@all'], target: { type: 'parent' }, decision: 'audit' },
      { name: 'deny-external-fatal', signals: ['@fatal'], target: { type: 'external' }, decision: 'deny', fallback: 'audit', message: 'Blocking signal to process outside session' },
      { name: 'deny-system', signals: ['@all'], target: { type: 'system' }, decision: 'deny', fallback: 'audit', message: 'Blocking signal to system process' },
    ],
    unixSocketRules: [
      { name: 'deny-system-sockets', paths: ['/var/run/**'], operations: ['connect', 'bind', 'listen', 'sendto'], decision: 'deny' },
    ],
    resourceLimits: {
      maxMemoryMb: 2048,
      cpuQuotaPercent: 50,
      pidsMax: 100,
      commandTimeout: '5m',
      sessionTimeout: '1h',
      idleTimeout: '15m',
    },
    auditSettings: {
      logAllowed: true,
      logDenied: true,
      logApproved: true,
      includeStdout: true,
      includeStderr: true,
    },
  };

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
