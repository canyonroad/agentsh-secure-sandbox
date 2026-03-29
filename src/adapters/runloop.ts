import type { SandboxAdapter, SecureConfig } from '../core/types.js';
import type { ServerConfigOpts } from '../core/config.js';
import type { PolicyDefinition } from '../policies/schema.js';
import { shellEscape, envPrefix } from '../core/shell.js';

/**
 * Wraps a Runloop Devbox into a SandboxAdapter.
 *
 * Runloop devboxes run as a non-root user (`runloop`) with passwordless
 * sudo. Use `runloopDefaults()` to get security configuration optimized
 * for Runloop's environment (seccomp + unix_sockets + FUSE deferred +
 * cgroups).
 *
 * The `devbox` parameter should be an object with `client` (a Runloop API
 * client) and `id` (the devbox ID). Typed as `any` to avoid a hard
 * dependency on the Runloop SDK.
 *
 * @example
 * ```ts
 * import Runloop from '@runloop/api-client';
 * import { secureSandbox, adapters } from '@agentsh/secure-sandbox';
 *
 * const client = new Runloop();
 * const devbox = await client.devboxes.createAndAwaitRunning({ blueprint_id: 'my-bp' });
 *
 * const adapter = adapters.runloop({ client, id: devbox.id });
 * const sandbox = await secureSandbox(adapter, adapters.runloopDefaults());
 * await sandbox.exec('echo hello');
 * await sandbox.stop();
 * ```
 */
export function runloop(devbox: any): SandboxAdapter {
  const client = devbox.client;
  const id = devbox.id;

  async function run(cmd: string): Promise<{ stdout: string; stderr: string; exitCode: number }> {
    try {
      const result = await client.devboxes.executeSync(id, { command: cmd });
      return {
        stdout: result.stdout ?? '',
        stderr: result.stderr ?? '',
        exitCode: result.exit_status ?? 0,
      };
    } catch (err: any) {
      return {
        stdout: err.stdout ?? '',
        stderr: err.stderr ?? err.message ?? '',
        exitCode: err.exit_status ?? err.exitCode ?? 1,
      };
    }
  }

  return {
    async exec(cmd, args, opts) {
      const command = `${envPrefix(opts?.env)}${opts?.sudo ? 'sudo ' : ''}${shellEscape(cmd, args)}`;

      if (opts?.detached) {
        run(`nohup ${command} > /dev/null 2>&1 &`).catch(() => {});
        return { stdout: '', stderr: '', exitCode: 0 };
      }

      if (opts?.cwd) {
        return run(`cd '${opts.cwd.replace(/'/g, "'\\''")}' && ${command}`);
      }

      return run(command);
    },

    async writeFile(path, content) {
      const text = Buffer.isBuffer(content) ? content.toString('utf-8') : content;
      try {
        await client.devboxes.writeFileContents(id, { file_path: path, contents: text });
      } catch (err: any) {
        throw new Error(
          `writeFile failed: ${err.message ?? err}`,
        );
      }
    },

    async readFile(path) {
      try {
        return await client.devboxes.readFileContents(id, { file_path: path });
      } catch (err: any) {
        throw new Error(
          `readFile failed: ${err.message ?? err}`,
        );
      }
    },

    async stop() {
      await client.devboxes.shutdown(id);
    },
  };
}

/**
 * Returns Runloop-optimized defaults for SecureConfig.
 *
 * Key characteristics:
 * - seccomp + unix_sockets enabled (atomic syscall interception)
 * - FUSE deferred (chmod'd via sudo on first session start)
 * - cgroups enabled for resource isolation
 * - ptrace disabled (unix_sockets wrapper provides enforcement)
 * - DLP with custom patterns for Runloop API keys and common secrets
 * - Policy translated from agentsh-runloop default.yaml (high-security,
 *   deny-by-default with explicit allows)
 *
 * Spread into your secureSandbox() call:
 *
 *   secureSandbox(runloop(devbox), { ...runloopDefaults(), ...yourOverrides })
 */
export function runloopDefaults(): Partial<SecureConfig> {
  const serverConfig: Omit<ServerConfigOpts, 'watchtower' | 'realPaths' | 'threatFeeds' | 'packageChecks'> = {
    grpc: { addr: '127.0.0.1:9090' },
    logging: { level: 'info', format: 'text', output: 'stderr' },
    sessions: {
      defaultTimeout: '1h',
      idleTimeout: '15m',
      cleanupInterval: '5m',
    },
    audit: { enabled: true, sqlitePath: '/var/lib/agentsh/events.db' },
    sandboxLimits: { maxMemoryMb: 4096, maxCpuPercent: 100, maxProcesses: 256 },
    allowDegraded: true,
    fuse: {
      deferred: true,
      deferredEnableCommand: ['sudo', '/bin/chmod', '666', '/dev/fuse'],
    },
    networkIntercept: { interceptMode: 'all', proxyListenAddr: '127.0.0.1:0' },
    seccompDetails: {
      fileMonitor: { enabled: true, enforceWithoutFuse: true },
    },
    cgroups: { enabled: true },
    unixSockets: { enabled: true },
    ptrace: { enabled: false },
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
        { name: 'runloop_key', display: 'RUNLOOP_KEY', regex: 'rl_[a-zA-Z0-9]{32,}' },
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

  // Policy translated from agentsh-runloop/default.yaml.
  // High-security, deny-by-default with explicit allows.
  // First-match-wins: order matters.
  const policy: PolicyDefinition = {
    file: [
      // --- Deny hostname config writes ---
      { deny: ['/etc/hostname', '/etc/hosts'], ops: ['write', 'create', 'delete'] },

      // --- Deny shell startup file writes (persistence prevention) ---
      { deny: [
        '~/.bashrc', '~/.bash_profile', '~/.profile', '~/.bash_login', '~/.bash_logout',
        '~/.zshrc', '~/.zprofile',
        '/root/.bashrc', '/root/.bash_profile', '/root/.profile',
        '/etc/bash.bashrc', '/etc/profile', '/etc/profile.d/**',
      ], ops: ['write', 'create', 'delete'] },

      // --- Allow reading shell startup files ---
      { allow: [
        '~/.bashrc', '~/.bash_profile', '~/.profile', '~/.bash_login', '~/.bash_logout',
        '~/.zshrc', '~/.zprofile',
      ], ops: ['read', 'open', 'stat'] },

      // --- Workspace: read, write, soft-delete ---
      { allow: ['/workspace', '/workspace/**'], ops: ['read', 'open', 'stat', 'list', 'readlink'] },
      { allow: ['/workspace', '/workspace/**'], ops: ['write', 'create', 'mkdir', 'chmod', 'rename'] },
      { softDelete: ['/workspace', '/workspace/**'] },

      // --- Temp directories (full access) ---
      { allow: ['/tmp/**', '/var/tmp/**'] },

      // --- Device nodes ---
      { allow: [
        '/dev/null', '/dev/zero', '/dev/urandom', '/dev/random',
        '/dev/stdin', '/dev/stdout', '/dev/stderr',
        '/dev/fd/**', '/dev/pts/**', '/dev/tty', '/dev/fuse',
      ] },

      // --- Home directory listing ---
      { allow: ['/home', '/home/**'], ops: ['read', 'open', 'stat', 'list', 'readlink'] },

      // --- agentsh internal paths ---
      { allow: [
        '/etc/agentsh/**', '/var/lib/agentsh/**',
        '/var/log/agentsh/**', '/usr/lib/agentsh/**',
      ], ops: ['read', 'open', 'stat', 'list'] },

      // --- Process and system info ---
      { allow: ['/proc/self/**', '/proc/version', '/proc/filesystems', '/proc/mounts'], ops: ['read', 'open', 'stat', 'list'] },

      // --- Block dangerous binaries (before system read) ---
      { deny: [
        '/usr/bin/sudo', '/usr/bin/su', '/usr/bin/pkexec', '/usr/bin/doas',
        '/bin/su', '/usr/sbin/chroot', '/usr/bin/nsenter', '/usr/bin/unshare',
      ] },

      // --- Block Docker/containerd socket ---
      { deny: [
        '/var/run/docker.sock', '/run/docker.sock',
        '/var/run/containerd/**', '/run/containerd/**',
      ] },

      // --- System paths (read-only) ---
      { allow: ['/usr/**', '/lib/**', '/lib64/**', '/bin/**', '/sbin/**'], ops: ['read', 'open', 'stat', 'list', 'readlink'] },

      // --- /etc minimal read ---
      { allow: [
        '/etc/hosts', '/etc/resolv.conf',
        '/etc/ssl/certs/**', '/etc/ca-certificates/**',
        '/etc/localtime', '/etc/passwd', '/etc/group',
        '/etc/nsswitch.conf', '/etc/ld.so.cache', '/etc/ld.so.conf', '/etc/ld.so.conf.d/**',
        '/etc/profile', '/etc/profile.d/**', '/etc/bash.bashrc', '/etc/bash.bash_logout',
        '/etc/environment', '/etc/default/**',
        '/etc/gitconfig', '/etc/git/**',
      ], ops: ['read', 'open', 'stat', 'list'] },

      // --- Deny credentials (approve → deny) ---
      { deny: ['~/.ssh/**', '/root/.ssh/**'] },
      { deny: ['~/.aws/**', '/root/.aws/**'] },
      { deny: ['~/.gcloud/**', '~/.azure/**', '~/.config/gcloud/**', '~/.kube/**'] },
      { deny: ['**/.env', '**/.env.*'] },
      { deny: ['~/.git-credentials', '**/.netrc'] },

      // --- Package caches (read-only) ---
      { allow: [
        '~/.npm/**', '~/.cache/**', '~/.cargo/**',
        '/root/.npm/**', '/root/.cache/**', '/root/.cargo/**',
      ], ops: ['read', 'open', 'stat', 'list'] },

      // --- Block /proc and /sys ---
      { deny: ['/proc/**', '/sys/**'] },

      // --- Default deny ---
      { deny: '**' },
    ],
    network: [
      // Localhost
      { allowCidrs: ['127.0.0.1/32', '::1/128'] },
      // Package registries
      { allow: ['registry.npmjs.org'], ports: [443] },
      { allow: ['pypi.org', 'files.pythonhosted.org'], ports: [443] },
      { allow: ['crates.io', 'static.crates.io'], ports: [443] },
      { allow: ['proxy.golang.org', 'sum.golang.org'], ports: [443] },
      // Block cloud metadata (SSRF protection)
      { deny: ['metadata.google.internal', 'metadata.goog'] },
      { denyCidrs: ['169.254.169.254/32', '100.100.100.200/32'] },
      // Block Kubernetes control plane
      { deny: ['kubernetes.default.svc', '*.svc.cluster.local'] },
      // Block private/internal networks
      { denyCidrs: ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '169.254.0.0/16'] },
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
        ],
      },
      // Dev tools
      {
        allow: [
          'git', 'node', 'npm', 'python', 'python3', 'pip', 'pip3',
          'cargo', 'go', 'make',
        ],
      },
      // Block raw network tools (reverse shell prevention)
      { deny: ['nc', 'netcat', 'ncat', 'socat', 'telnet', 'ssh', 'scp', 'rsync'] },
      // Block system administration
      {
        deny: [
          'shutdown', 'reboot', 'systemctl', 'service',
          'mount', 'umount', 'dd', 'fdisk', 'mkfs',
          'kill', 'killall', 'pkill',
          'hostname', 'domainname', 'hostnamectl',
        ],
      },
      // Block container escape tools
      { deny: ['sudo', 'su', 'chroot', 'nsenter', 'unshare', 'docker', 'podman', 'nerdctl'] },
      // Allow all other (file + network rules are the real enforcement)
      { allow: '*' },
    ],
    envPolicy: {
      deny: [
        '*_SECRET*', '*_PASSWORD*', '*_PRIVATE_KEY*', '*_API_KEY*', '*_ACCESS_KEY*', '*_TOKEN',
        'ANTHROPIC_API_KEY', 'OPENAI_API_KEY', 'RUNLOOP_API_KEY',
        'GITHUB_TOKEN', 'GH_TOKEN', 'NPM_TOKEN',
        'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN',
        'GOOGLE_APPLICATION_CREDENTIALS',
      ],
      blockIteration: true,
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
    installStrategy: 'download',
    realPaths: true,
    serverConfig,
  };
}
