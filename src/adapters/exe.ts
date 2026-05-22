import { execFile as execFileCb } from 'node:child_process';
import type { SandboxAdapter, SecureConfig } from '../core/types.js';
import type { ServerConfigOpts } from '../core/config.js';
import type { PolicyDefinition } from '../policies/schema.js';
import { shellEscape, envPrefix } from '../core/shell.js';
import { KNOWN_MITIGATIONS } from '../core/mitigations.js';

/** Promisified execFile that preserves stdout/stderr on both success and error. */
function execFileAsync(
  cmd: string,
  args: string[],
  opts: { timeout?: number; maxBuffer?: number },
): Promise<{ stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    execFileCb(cmd, args, opts, (err, stdout, stderr) => {
      if (err) {
        (err as any).stdout = (stdout as string) ?? '';
        (err as any).stderr = (stderr as string) ?? '';
        reject(err);
      } else {
        resolve({ stdout: (stdout as string) ?? '', stderr: (stderr as string) ?? '' });
      }
    });
  });
}

const SSH_OPTS = [
  '-o', 'StrictHostKeyChecking=no',
  '-o', 'UserKnownHostsFile=/dev/null',
  '-o', 'LogLevel=ERROR',
];

/** Strip agentsh debug noise that leaks through SSH stderr. */
const NOISE_PREFIXES = ['landlock:', 'ptrace:', 'agentsh:', 'seccomp:', '[agentsh]'];

// Agentsh ≥0.20 uses Go's slog text handler which prefixes lines with a
// level token ("INFO ", "WARN ", etc.) before the actual content. Strip
// that prefix once before testing against NOISE_PREFIXES so e.g.
// "INFO seccomp: filter loaded …" still matches the "seccomp:" entry.
const SLOG_LEVEL = /^(?:debug|info|warn|warning|error)\s+/i;

function filterNoise(text: string): string {
  return text
    .split('\n')
    .filter(line => {
      const trimmed = line.trimStart().replace(SLOG_LEVEL, '').toLowerCase();
      return !NOISE_PREFIXES.some(p => trimmed.startsWith(p.toLowerCase()));
    })
    .join('\n');
}

// ── exec.dev gateway wrapper ──────────────────────────────────
//
// The exe.dev SSH gateway forces a PTY on the inner ssh hop.  A PTY:
//   • masks the inner command's exit code (always reports 0)
//   • merges stderr into stdout
//   • inserts CR characters into the byte stream
//
// The gateway also rejects SSH options like `-T` / `-o RequestTTY=no`,
// so we can't disable the PTY.  Instead we wrap every user command in a
// shell snippet that:
//   1. base64-decodes the user command (so quoting/binary survive both
//      ssh hops cleanly)
//   2. runs it in a subshell with stdout/stderr redirected to temp files
//   3. emits markers + base64 of each stream + the captured exit code
//
// On the host side, parseWrappedOutput() locates the markers in the raw
// SSH output (any PTY noise lands outside the markers and is ignored)
// and decodes the payloads.  This restores faithful exit codes, exact
// stdout/stderr separation, and binary-safe content.

const MARKER_OUT = '__AGENTSH_EXE_OUT__';
const MARKER_ERR = '__AGENTSH_EXE_ERR__';
const MARKER_EXIT = '__AGENTSH_EXE_EXIT__=';

function buildWrapper(userCommand: string): string {
  const cmdB64 = Buffer.from(userCommand, 'utf-8').toString('base64');
  // Built using only double quotes so the entire wrapper can be safely
  // wrapped in single quotes for the gateway shell layer.  cmdB64 is
  // base64 ([A-Za-z0-9+/=]) so it never contains shell-special chars.
  return [
    `__CMD__="${cmdB64}"`,
    `__SCRIPT__=$(printf "%s" "$__CMD__" | base64 -d)`,
    `( eval "$__SCRIPT__" ) > /tmp/agentsh-ssh-out.$$ 2> /tmp/agentsh-ssh-err.$$`,
    `__X__=$?`,
    `printf "${MARKER_OUT}"`,
    `base64 -w0 /tmp/agentsh-ssh-out.$$`,
    `printf "${MARKER_ERR}"`,
    `base64 -w0 /tmp/agentsh-ssh-err.$$`,
    `printf "${MARKER_EXIT}%s\\n" "$__X__"`,
    `rm -f /tmp/agentsh-ssh-out.$$ /tmp/agentsh-ssh-err.$$`,
  ].join('; ');
}

function parseWrappedOutput(
  raw: string,
): { stdout: string; stderr: string; exitCode: number } | null {
  const outIdx = raw.indexOf(MARKER_OUT);
  const errIdx = raw.indexOf(MARKER_ERR);
  const exitIdx = raw.indexOf(MARKER_EXIT);
  if (
    outIdx < 0 ||
    errIdx < 0 ||
    exitIdx < 0 ||
    outIdx >= errIdx ||
    errIdx >= exitIdx
  ) {
    return null;
  }
  // base64 charset is [A-Za-z0-9+/=] — no whitespace — so any CR/LF inserted
  // by the gateway PTY between segments is harmless to strip.
  const cleanB64 = (s: string) => s.replace(/[\r\n\s]/g, '');
  const outB64 = cleanB64(raw.slice(outIdx + MARKER_OUT.length, errIdx));
  const errB64 = cleanB64(raw.slice(errIdx + MARKER_ERR.length, exitIdx));
  const exitMatch = raw.slice(exitIdx + MARKER_EXIT.length).match(/^(\d+)/);
  if (!exitMatch) return null;
  return {
    stdout: Buffer.from(outB64, 'base64').toString('utf-8'),
    stderr: Buffer.from(errB64, 'base64').toString('utf-8'),
    exitCode: parseInt(exitMatch[1], 10),
  };
}

/**
 * Wraps an exe.dev VM into a SandboxAdapter.
 *
 * exe.dev VMs are accessed via SSH through the exe.dev gateway.
 * Commands are routed as: `ssh exe.dev ssh <vmName> <command>`.
 * The VM must already exist (created via `ssh exe.dev new`).
 *
 * exe.dev VMs are persistent — `stop()` is a no-op.  Destroy the
 * VM externally with `ssh exe.dev rm <vmName>`.
 *
 * Use `exeDefaults()` for security configuration optimized for
 * exe.dev's environment (full enforcement: ptrace + seccomp +
 * landlock + FUSE + cgroups).
 *
 * @example
 * ```ts
 * import { secureSandbox, adapters } from '@agentsh/secure-sandbox';
 *
 * // VM already created: ssh exe.dev new --name=my-vm --image=ubuntu:22.04
 * const adapter = adapters.exe('my-vm');
 * const sandbox = await secureSandbox(adapter, adapters.exeDefaults());
 * await sandbox.exec('echo hello');
 * ```
 */
export function exe(vmName: string): SandboxAdapter {
  /**
   * Execute a command on the VM via the exe.dev SSH gateway.
   *
   * The gateway forces a PTY on the inner ssh hop, so commands are wrapped
   * with buildWrapper() to recover faithful exit codes and clean stdout /
   * stderr separation. Default timeout: 120s.
   */
  async function ssh(cmd: string, timeout = 120_000): Promise<{ stdout: string; stderr: string; exitCode: number }> {
    const wrapper = buildWrapper(cmd);
    // wrapper is built with no single quotes, so wrapping the entire script
    // in single quotes for the gateway shell is safe without escaping.
    const args = [...SSH_OPTS, 'exe.dev', `ssh ${vmName} '${wrapper}'`];
    let raw: { stdout: string; stderr: string };
    let outerExit = 0;
    try {
      raw = await execFileAsync('ssh', args, {
        timeout,
        maxBuffer: 50 * 1024 * 1024,
      });
    } catch (err: any) {
      raw = {
        stdout: err.stdout ?? '',
        stderr: err.stderr ?? err.message ?? '',
      };
      outerExit = typeof err.code === 'number' ? err.code : 1;
    }
    const parsed = parseWrappedOutput(raw.stdout);
    if (parsed) {
      // Wrapper produced markers — trust its exit code and the captured
      // streams, but still strip agentsh noise lines that the user command
      // (e.g. `agentsh detect`) emits to stderr alongside structured output.
      return {
        stdout: parsed.stdout,
        stderr: filterNoise(parsed.stderr),
        exitCode: parsed.exitCode,
      };
    }
    // No markers found — gateway/network/SSH error before the wrapper ran.
    // Surface raw output (with noise filtered) and a non-zero exit so callers
    // notice the failure rather than silently parsing garbage.
    return {
      stdout: raw.stdout,
      stderr: filterNoise(raw.stderr),
      exitCode: outerExit !== 0 ? outerExit : 1,
    };
  }

  return {
    async exec(cmd, args, opts) {
      // exe.dev VMs always SSH in as root, so opts.sudo is redundant — and
      // worse, the default ubuntu:22.04 image has no sudo binary at all, so
      // prepending it would break callers like provision.ts that pass
      // { sudo: true } as an "elevate if needed" hint. Drop the sudo prefix
      // unconditionally; we already have the privileges it would request.
      const command = `${envPrefix(opts?.env)}${shellEscape(cmd, args)}`;

      if (opts?.detached) {
        ssh(`nohup ${command} > /dev/null 2>&1 &`).catch(() => {});
        return { stdout: '', stderr: '', exitCode: 0 };
      }

      if (opts?.cwd) {
        return ssh(`cd '${opts.cwd.replace(/'/g, "'\\''")}' && ${command}`);
      }

      return ssh(command);
    },

    async writeFile(path, content) {
      const buf = Buffer.isBuffer(content) ? content : Buffer.from(content);
      const b64 = buf.toString('base64');
      const result = await ssh(
        `printf '%s' '${b64}' | base64 -d > '${path.replace(/'/g, "'\\''")}'`,
      );
      if (result.exitCode !== 0) {
        throw new Error(`writeFile failed (exit ${result.exitCode}): ${result.stderr}`);
      }
    },

    async readFile(path) {
      const result = await ssh(`cat '${path.replace(/'/g, "'\\''")}'`);
      if (result.exitCode !== 0) {
        throw new Error(`readFile failed (exit ${result.exitCode}): ${result.stderr}`);
      }
      return result.stdout;
    },

    async stop() {
      // No-op — exe.dev VMs are persistent.
      // Destroy externally: ssh exe.dev rm <vmName>
    },

    async fileExists(path) {
      const result = await ssh(`test -f '${path.replace(/'/g, "'\\''")}'`);
      return result.exitCode === 0;
    },
  };
}

/**
 * Returns exe.dev-optimized defaults for SecureConfig.
 *
 * Key characteristics:
 * - Full enforcement: ptrace + seccomp + landlock + FUSE + cgroups
 * - allowDegraded: false (exe.dev has all kernel capabilities)
 * - FUSE deferred mode with soft-delete quarantine
 * - DLP with custom patterns for common AI/cloud API keys
 * - High-security, deny-by-default policy with explicit allows
 * - Conservative resource limits (2 GB RAM, 50% CPU, 100 PIDs)
 * - Workspace at /root and /workspace
 *
 * Spread into your secureSandbox() call:
 *
 *   secureSandbox(exe('my-vm'), { ...exeDefaults(), ...yourOverrides })
 */
export function exeDefaults(): Partial<SecureConfig> {
  const serverConfig: Omit<ServerConfigOpts, 'watchtower' | 'realPaths' | 'threatFeeds' | 'packageChecks'> = {
    grpc: { addr: '127.0.0.1:9090' },
    serverTimeouts: { readTimeout: '30s', writeTimeout: '60s', maxRequestSize: '10MB' },
    logging: { level: 'info', format: 'text', output: 'stderr' },
    sessions: {
      maxSessions: 100,
      defaultTimeout: '1h',
      idleTimeout: '15m',
      cleanupInterval: '5m',
    },
    audit: { enabled: true, sqlitePath: '/var/lib/agentsh/events.db' },
    sandboxLimits: { maxMemoryMb: 4096, maxCpuPercent: 100, maxProcesses: 256 },
    allowDegraded: false,
    fuse: {
      deferred: true,
      deferredMarkerFile: '/tmp/.agentsh-fuse-enabled',
      deferredEnableCommand: ['/bin/chmod', '666', '/dev/fuse'],
    },
    networkIntercept: { interceptMode: 'all', proxyListenAddr: '127.0.0.1:0' },
    seccompDetails: {
      execve: false, // ptrace handles execve; MUST remain false
      fileMonitor: { enabled: true, enforceWithoutFuse: true },
      mitigationSets: [KNOWN_MITIGATIONS.dirtyfragConservative],
    },
    cgroups: { enabled: true },
    unixSockets: { enabled: true },
    ptrace: {
      enabled: true,
      trace: {
        execve: true,
        file: false,   // seccomp file_monitor handles this
        network: false, // network proxy handles this
        signal: false,  // seccomp handles this
      },
      performance: {
        seccompPrefilter: true,
      },
    },
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
    development: { disableAuth: true, verboseErrors: true },
  };

  // Policy translated from agentsh-exe.dev/default.yaml.
  // High-security, deny-by-default with explicit allows.
  // First-match-wins: order matters.
  const policy: PolicyDefinition = {
    file: [
      // --- Deny dangerous binaries (before system read) ---
      { deny: [
        '/usr/bin/sudo', '/usr/bin/su', '/usr/bin/pkexec', '/usr/bin/doas',
        '/bin/su', '/usr/sbin/chroot', '/usr/bin/nsenter', '/usr/bin/unshare',
      ] },

      // --- Block exe.dev infrastructure ---
      { deny: [
        '/usr/bin/shelley', '/usr/local/bin/shelley',
        '/etc/systemd/**', '/run/systemd/**',
      ] },

      // --- Deny credentials (approve → deny: TypeScript schema lacks approve for files) ---
      { deny: ['~/.ssh/**', '/root/.ssh/**'] },
      { deny: ['~/.aws/**', '/root/.aws/**'] },
      { deny: ['~/.gcloud/**', '~/.azure/**', '~/.config/gcloud/**', '~/.kube/**',
               '/root/.gcloud/**', '/root/.azure/**', '/root/.config/gcloud/**', '/root/.kube/**'] },
      { deny: ['**/.env', '**/.env.*'] },
      { deny: ['~/.git-credentials', '/root/.git-credentials', '**/.netrc'] },

      // --- Workspace: read, write, soft-delete ---
      { allow: ['/root', '/root/**', '/workspace', '/workspace/**'],
        ops: ['read', 'write', 'create', 'open', 'stat', 'list', 'readlink', 'mkdir', 'chmod', 'rename'] },
      { softDelete: ['/root', '/root/**', '/workspace', '/workspace/**'] },

      // --- Temp directories (full access) ---
      { allow: ['/tmp/**', '/var/tmp/**'] },

      // --- System paths (read-only) ---
      { allow: ['/usr/**', '/lib/**', '/lib64/**', '/bin/**', '/sbin/**'],
        ops: ['read', 'open', 'stat', 'list', 'readlink'] },

      // --- Device nodes ---
      { allow: [
        '/dev/null', '/dev/zero', '/dev/tty', '/dev/pts/**',
        '/dev/urandom', '/dev/random', '/dev/shm/**',
        '/dev/stdin', '/dev/stdout', '/dev/stderr', '/dev/fd/**',
      ], ops: ['read', 'write', 'create', 'open', 'stat'] },

      // --- Sensitive /etc files (deny before /etc read) ---
      { deny: ['/etc/shadow', '/etc/gshadow', '/etc/sudoers', '/etc/sudoers.d/**'] },

      // --- /etc minimal read ---
      { allow: [
        '/etc/hosts', '/etc/resolv.conf',
        '/etc/ssl/**', '/etc/ca-certificates/**',
        '/etc/localtime', '/etc/timezone',
        '/etc/ld.so.cache', '/etc/ld.so.preload', '/etc/ld.so.nohwcap',
        '/etc/ld.so.conf', '/etc/ld.so.conf.d/**',
        '/etc/nsswitch.conf', '/etc/passwd', '/etc/group',
        '/etc/fuse.conf', '/etc/gai.conf',
        '/etc/mime.types', '/etc/protocols', '/etc/services',
      ], ops: ['read', 'open', 'stat', 'readlink'] },

      // --- /proc/self for process introspection ---
      { allow: ['/proc/self/**', '/proc/thread-self/**'],
        ops: ['read', 'open', 'stat', 'list', 'readlink'] },

      // --- Package caches (read-only) ---
      { allow: [
        '~/.npm/**', '~/.cache/**', '~/.cargo/**',
        '/root/.npm/**', '/root/.cache/**', '/root/.cargo/**',
      ], ops: ['read', 'open', 'stat', 'list'] },

      // --- agentsh runtime ---
      { allow: ['/var/lib/agentsh/**', '/var/log/agentsh/**'],
        ops: ['read', 'write', 'open', 'stat', 'list', 'readlink'] },

      // --- Secrets and credentials ---
      { deny: ['**/credentials*', '**/*.pem', '**/*.key'] },
      { deny: ['/proc/*/environ'] },

      // --- Shell config injection (deny writes) ---
      { deny: [
        '~/.bashrc', '~/.zshrc', '~/.profile', '~/.bash_profile',
        '/root/.bashrc', '/root/.zshrc', '/root/.profile', '/root/.bash_profile',
      ], ops: ['write', 'create'] },
      // --- Hostname config (deny writes) ---
      { deny: ['/etc/hostname', '/etc/hosts'], ops: ['write', 'create'] },
      // --- Docker socket ---
      { deny: ['/var/run/docker.sock', '/run/docker.sock'] },
      // --- Credential stores ---
      { deny: ['~/.gitconfig', '~/.curlrc', '~/.wgetrc'] },
      // --- Agent config files (deny writes) ---
      { deny: ['**/.cursorrules', '**/CLAUDE.md', '**/copilot-instructions.md'], ops: ['write', 'create', 'delete'] },

      // --- Block /proc and /sys writes ---
      { deny: ['/proc/**', '/sys/**'] },

      // --- Default deny (catch-all) ---
      { deny: '**' },
    ],
    network: [
      // Localhost (agentsh server + embedded proxy)
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
      // Dev tools
      {
        allow: [
          'git', 'node', 'npm', 'python', 'python3', 'pip', 'pip3',
          'cargo', 'go', 'make',
        ],
      },
      // Deny raw network tools (reverse shell prevention)
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
      // Deny system package managers
      { deny: ['apt', 'apt-get', 'yum', 'dnf', 'brew'] },
      // Deny exe.dev interference
      { deny: ['shelley', 'iptables', 'ip6tables', 'nft', 'tc', 'ip'] },
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
    installStrategy: 'download',
    realPaths: true,
    serverConfig,
  };
}
