import type { SandboxAdapter, SecureConfig } from '../core/types.js';
import type { ServerConfigOpts } from '../core/config.js';
import { generateServerConfig } from '../core/config.js';
import type { PolicyDefinition } from '../policies/schema.js';
import { serializePolicy, systemPolicyYaml } from '../policies/serialize.js';
import { shellEscape, envPrefix } from '../core/shell.js';
import { CHECKSUMS } from '../core/integrity.js';
import { KNOWN_MITIGATIONS } from '../core/mitigations.js';

const AGENTSH_VERSION = '0.20.5';
const AGENTSH_SHA256 = CHECKSUMS[AGENTSH_VERSION].linux_amd64;

const SEMVER_RE = /^\d+\.\d+\.\d+(?:-[a-zA-Z0-9.-]+)?$/;

// Cold-start warmup transient: for the first command(s) after the server
// reports healthy, the agentsh shell shim's per-command seccomp wrap setup can
// briefly fail while the server settles. These signatures are agentsh
// shim/server errors (distinct from a command's own non-zero exit), so they
// are safe to retry. (The *deterministic* fail-close — the server aborting the
// wrap when the cgroup memory.max write EPERMs — is handled separately by
// disabling cgroups in freestyleDefaults; this only mops up the warmup window.)
const TRANSIENT_SHIM_RE =
  /server rejected wrap setup|kernel install fail-closed|forward notify fd failed|ACK handshake failed|INTERNAL_ERROR: Internal server error/;

function isTransientShimError(r: { exitCode: number; stderr: string }): boolean {
  return r.exitCode !== 0 && TRANSIENT_SHIM_RE.test(r.stderr);
}

const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

const INSTALL_SCRIPT = [
  '#!/bin/bash',
  'set -eux',
  `AGENTSH_VERSION="${AGENTSH_VERSION}"`,
  `AGENTSH_SHA256="${AGENTSH_SHA256}"`,
  'URL="https://github.com/canyonroad/agentsh/releases/download/v${AGENTSH_VERSION}/agentsh_${AGENTSH_VERSION}_linux_amd64.tar.gz"',
  'curl -fsSL "${URL}" -o /tmp/agentsh.tar.gz',
  'echo "${AGENTSH_SHA256}  /tmp/agentsh.tar.gz" | sha256sum -c -',
  'tar xz -C /tmp/ -f /tmp/agentsh.tar.gz',
  'install -m 0755 /tmp/agentsh /usr/local/bin/agentsh',
  'install -m 0755 /tmp/agentsh-shell-shim /usr/bin/agentsh-shell-shim',
  'install -m 0755 /tmp/agentsh-unixwrap /usr/local/bin/agentsh-unixwrap',
  'rm -f /tmp/agentsh.tar.gz /tmp/agentsh /tmp/agentsh-shell-shim /tmp/agentsh-unixwrap',
  'mkdir -p /etc/agentsh/system /var/lib/agentsh/quarantine /var/lib/agentsh/sessions /var/log/agentsh /home/user',
  'chmod 755 /etc/agentsh /etc/agentsh/system /var/lib/agentsh /var/lib/agentsh/quarantine /var/lib/agentsh/sessions /var/log/agentsh',
  'echo "root ALL=(ALL) NOPASSWD: /usr/local/bin/agentsh" >> /etc/sudoers',
  'echo "root ALL=(ALL) NOPASSWD: /bin/chmod 666 /dev/fuse" >> /etc/sudoers',
  'echo "root ALL=(ALL) NOPASSWD: /bin/chmod 600 /dev/fuse" >> /etc/sudoers',
  'echo "root ALL=(ALL) NOPASSWD: /bin/mknod /dev/fuse c 10 229" >> /etc/sudoers',
  'echo "user_allow_other" >> /etc/fuse.conf',
  '/usr/local/bin/agentsh --version',
].join('\n');

const STARTUP_SCRIPT = [
  '#!/bin/bash',
  '# Restrict /dev/fuse to prevent any FUSE mount during snapshot',
  'sudo /bin/chmod 600 /dev/fuse 2>/dev/null || true',
  '',
  '# Start agentsh server in background (deferred FUSE: mounts on first exec).',
  '# --config is explicit: agentsh\'s default config search does not include',
  '# /etc/agentsh/config.yml, so without this our server config is ignored.',
  '/usr/local/bin/agentsh server --config /etc/agentsh/config.yml >> /var/log/agentsh/server.log 2>&1 &',
  'SERVER_PID=$!',
  '',
  '# Wait for server to be ready (health check loop)',
  'for i in $(seq 1 15); do',
  '  if curl -sf http://127.0.0.1:18080/health >/dev/null 2>&1; then break; fi',
  '  sleep 1',
  'done',
  '',
  '# Install shell shim (replaces /bin/bash with agentsh shim)',
  'sudo /usr/local/bin/agentsh shim install-shell --root / --shim /usr/bin/agentsh-shell-shim --bash --i-understand-this-modifies-the-host',
  '',
  '# Warm up the shim',
  '/bin/bash -c "echo shim warmup ok" 2>/dev/null || true',
  '',
  'echo "agentsh ready"',
  '',
  '# Keep the script alive so systemd does not kill the service cgroup',
  'wait $SERVER_PID',
].join('\n');

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
 * import { Freestyle, VmSpec } from 'freestyle-sandboxes';
 * import { secureSandbox } from '@agentsh/secure-sandbox';
 * import { freestyle, freestyleDefaults } from '@agentsh/secure-sandbox/adapters/freestyle';
 *
 * const fs = new Freestyle({ apiKey: process.env.FREESTYLE_API_KEY });
 * const { vm } = await fs.vms.create({ spec: new VmSpec() });
 * const sandbox = await secureSandbox(freestyle(vm), freestyleDefaults());
 * await sandbox.exec('echo hello');
 * await sandbox.stop();
 * ```
 */
export function freestyle(vm: any): SandboxAdapter {
  async function runOnce(command: string, timeoutMs?: number): Promise<{ stdout: string; stderr: string; exitCode: number }> {
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

  // Retry only transient shim warmup failures (never a command's own non-zero
  // exit). Up to 3 retries with escalating backoff covers the brief settling
  // window observed right after the server reports healthy.
  async function run(command: string, timeoutMs?: number): Promise<{ stdout: string; stderr: string; exitCode: number }> {
    let result = await runOnce(command, timeoutMs);
    for (let attempt = 1; attempt <= 3 && isTransientShimError(result); attempt++) {
      await sleep(250 * attempt);
      result = await runOnce(command, timeoutMs);
    }
    return result;
  }

  return {
    async exec(cmd, args, opts) {
      // Note: opts.sudo is intentionally ignored. Freestyle VMs run commands as
      // root, so sudo is unnecessary; worse, freestyleDefaults' policy denies
      // the sudo binary, so a `sudo …` prefix fails with exit 126 ("sudo:
      // Permission denied"). Provisioning issues chmod/chown/mkdir with
      // sudo:true — running them bare (as root) is correct here.
      const inner = `${envPrefix(opts?.env)}${shellEscape(cmd, args)}`;
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
      // Use a retrying `test -e` via exec rather than vm.fs.exists: the SDK's
      // exists() also shells out (`test -e`) through the shim, so it is subject
      // to the same warmup transient — routing it through run() gives it the
      // retry. A genuinely missing path returns exit 1 with empty stderr, which
      // is not a transient signature, so it is not retried.
      const quoted = `'${path.replace(/'/g, "'\\''")}'`;
      const result = await run(`test -e ${quoted}`);
      return result.exitCode === 0;
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
      mitigationSets: [KNOWN_MITIGATIONS.dirtyfragConservative],
    },
    // Freestyle runs the sandbox under a nested cgroup
    // (freestyle-supervisor.service) whose subtree_control can't be edited, so
    // agentsh can't enable controllers and even its fallback agentsh.slice
    // memory.max is not writable. With cgroups enabled, the server's
    // per-command wrap setup writes memory.max BEFORE acking the shim; that
    // write EPERMs, the server aborts the wrap and closes the socket, and the
    // fail-closed shim aborts every command with exit 126 ("server rejected
    // wrap setup"). Disabling cgroups avoids that write. The limits weren't
    // enforceable on Freestyle anyway (documented gap), and the inner policy
    // resourceLimits below stay as advisory metadata.
    cgroups: { enabled: false },
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

/**
 * Bake agentsh into a Freestyle VmSpec via two systemd services: an
 * oneshot installer and the agentsh server. Call this on a fresh VmSpec,
 * then `.snapshot()` the result to push everything into the cached
 * snapshot layer before passing it to `fs.vms.create`.
 *
 * Note: `.snapshot()` must be called AFTER configureFreestyleSpec — it
 * pushes the current outer layer down to become the inner snapshot
 * template. Calling `.snapshot()` first leaves an empty snapshot and
 * the agentsh install ends up at the runtime layer, which the
 * Freestyle API rejects.
 *
 * The spec defaults the policy + server config to `freestyleDefaults()`.
 * Override either via `opts.policyYaml` or `opts.configYaml` with a
 * pre-serialized YAML string (use `serializePolicy` and
 * `generateServerConfig` from the library's internals).
 *
 * `spec` is typed `any` so callers can import `VmSpec` from
 * `freestyle-sandboxes` without making it a hard dependency.
 *
 * @example
 * ```ts
 * import { Freestyle, VmSpec } from 'freestyle-sandboxes';
 * import { configureFreestyleSpec, freestyle, freestyleDefaults } from '@agentsh/secure-sandbox/adapters/freestyle';
 *
 * const fs = new Freestyle({ apiKey: process.env.FREESTYLE_API_KEY });
 * const spec = configureFreestyleSpec(new VmSpec()).snapshot();
 * const { vm } = await fs.vms.create({ spec });
 * const sandbox = await secureSandbox(freestyle(vm), {
 *   ...freestyleDefaults(),
 *   installStrategy: 'preinstalled',
 * });
 * ```
 */
export function configureFreestyleSpec(
  spec: any,
  opts?: { agentshVersion?: string; policyYaml?: string; configYaml?: string },
): any {
  const defaults = freestyleDefaults();
  const policyYaml = opts?.policyYaml
    ?? serializePolicy(defaults.policy as PolicyDefinition);
  const configYaml = opts?.configYaml
    ?? generateServerConfig(defaults.serverConfig as ServerConfigOpts);

  if (opts?.agentshVersion !== undefined && !SEMVER_RE.test(opts.agentshVersion)) {
    throw new Error(`configureFreestyleSpec: invalid agentshVersion ${opts.agentshVersion}; expected semver like "0.17.0"`);
  }

  const installScript = opts?.agentshVersion
    ? INSTALL_SCRIPT.replace(`AGENTSH_VERSION="${AGENTSH_VERSION}"`, `AGENTSH_VERSION="${opts.agentshVersion}"`)
    : INSTALL_SCRIPT;

  return spec
    .aptDeps('ca-certificates', 'curl', 'jq', 'libseccomp2', 'sudo', 'fuse3', 'python3', 'file', 'sqlite3')
    .additionalFiles({
      '/opt/install-agentsh.sh': { content: installScript },
      '/etc/agentsh/config.yml': { content: configYaml },
      '/etc/agentsh/policy.yml': { content: policyYaml },
      '/etc/agentsh/system/policy.yml': { content: systemPolicyYaml() },
      '/opt/agentsh-startup.sh': { content: STARTUP_SCRIPT },
      '/etc/environment': {
        content: [
          'AGENTSH_SERVER=http://127.0.0.1:18080',
          'AGENTSH_SHIM_FORCE=1',
        ].join('\n'),
      },
    })
    .systemdService({
      name: 'install-agentsh',
      mode: 'oneshot',
      exec: ['bash /opt/install-agentsh.sh'],
      wantedBy: ['multi-user.target'],
    })
    .systemdService({
      name: 'agentsh',
      mode: 'service',
      exec: ['bash /opt/agentsh-startup.sh'],
      env: {
        AGENTSH_SERVER: 'http://127.0.0.1:18080',
        AGENTSH_SHIM_FORCE: '1',
      },
      after: ['install-agentsh.service'],
      requires: ['install-agentsh.service'],
      wantedBy: ['multi-user.target'],
    });
}
