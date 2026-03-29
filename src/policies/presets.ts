import type { PolicyDefinition } from './schema.js';
import { merge } from './merge.js';

// ─── agentDefault ──────────────────────────────────────────

/**
 * Comprehensive policy for AI coding agents. This is the DEFAULT policy
 * used when no policy is specified. Aligned with production agent-default.yaml
 * from agentsh v0.16.9. Designed to work with all enforcement modes
 * including file_monitor (seccomp/ptrace).
 */
export function agentDefault(
  extensions?: Partial<PolicyDefinition>,
): PolicyDefinition {
  const base: PolicyDefinition = {
    file: [
      // --- Deny dangerous binaries (before system read allows them) ---
      { deny: [
        '/usr/bin/sudo', '/usr/bin/su', '/usr/bin/pkexec', '/usr/bin/doas',
        '/bin/su', '/usr/sbin/chroot', '/usr/bin/nsenter', '/usr/bin/unshare',
      ] },

      // --- Workspace ---
      { allow: '/workspace/**', ops: ['read', 'write', 'create', 'open', 'stat', 'list', 'readlink', 'mkdir', 'chmod', 'rename'] },
      { softDelete: '/workspace/**' },

      // --- Temp directories (full access) ---
      { allow: ['/tmp/**', '/var/tmp/**'] },

      // --- System read (libraries, binaries, runtimes, devices) ---
      { allow: ['/usr/**', '/lib/**', '/lib64/**', '/bin/**', '/sbin/**', '/opt/**', '/dev/**'], ops: ['read', 'open', 'stat', 'list', 'readlink'] },

      // --- Device file writes (safe nodes) ---
      { allow: [
        '/dev/null', '/dev/zero', '/dev/tty', '/dev/pts/**',
        '/dev/urandom', '/dev/random', '/dev/shm/**',
      ], ops: ['write', 'create', 'open'] },

      // --- Sensitive /etc files (deny before /etc read) ---
      { deny: ['/etc/shadow', '/etc/gshadow', '/etc/sudoers', '/etc/sudoers.d/**'] },

      // --- /etc minimal read ---
      { allow: [
        '/etc/hosts', '/etc/resolv.conf',
        '/etc/ssl/**', '/etc/ca-certificates/**',
        '/etc/localtime', '/etc/timezone',
        '/etc/ld.so.cache', '/etc/ld.so.preload', '/etc/ld.so.conf', '/etc/ld.so.conf.d/**',
        '/etc/nsswitch.conf', '/etc/passwd', '/etc/group',
        '/etc/mime.types', '/etc/protocols', '/etc/services',
        '/etc/gai.conf',
      ], ops: ['read', 'open', 'stat', 'readlink'] },

      // --- /proc/self for process introspection ---
      { allow: ['/proc/self/**', '/proc/thread-self/**'], ops: ['read', 'open', 'stat', 'list', 'readlink'] },

      // --- Package caches (full access for dev workflows) ---
      { allow: [
        '~/.npm/**', '~/.yarn/**', '~/.pnpm-store/**',
        '~/.cache/**', '~/.cargo/**', '~/go/**',
        '~/.local/**', '~/.rustup/**', '~/.bun/**',
        '/root/.npm/**', '/root/.yarn/**', '/root/.pnpm-store/**',
        '/root/.cache/**', '/root/.cargo/**', '/root/go/**',
        '/root/.local/**', '/root/.rustup/**', '/root/.bun/**',
      ] },

      // --- agentsh runtime ---
      { allow: ['/var/lib/agentsh/**', '/var/log/agentsh/**'], ops: ['read', 'write', 'open', 'stat', 'list', 'readlink'] },

      // --- Secrets and credentials ---
      { deny: ['**/.env', '**/.env.*', '**/credentials*', '**/*.pem', '**/*.key'] },
      { deny: ['/workspace/.git/config', '/workspace/.netrc'] },
      { deny: ['~/.ssh/**', '/proc/*/environ'] },
      { deny: ['~/.aws/**', '~/.gcp/**', '~/.azure/**', '~/.config/gcloud/**'] },

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
      { deny: ['~/.gitconfig', '~/.netrc', '~/.curlrc', '~/.wgetrc'] },
      // --- Agent config files (deny writes) ---
      { deny: ['**/.cursorrules', '**/CLAUDE.md', '**/copilot-instructions.md'], ops: ['write', 'create', 'delete'] },

      // --- Sensitive /proc entries ---
      { deny: ['/proc/self/environ', '/proc/thread-self/environ', '/proc/*/environ', '/proc/*/mem', '/proc/kcore'] },
      // --- Block /proc and /sys writes ---
      { deny: ['/proc/**', '/sys/**'], ops: ['write', 'create', 'chmod', 'delete', 'rename', 'mkdir'] },

      // --- Default deny (catch-all) ---
      { deny: '**' },
    ],
    network: [
      // LLM providers
      {
        allow: [
          'api.anthropic.com', '*.anthropic.com',
          'api.openai.com', '*.openai.com',
          'generativelanguage.googleapis.com', '*.googleapis.com',
        ],
        ports: [443],
      },
      // npm registry
      {
        allow: ['registry.npmjs.org', '*.npmjs.org', '*.npmjs.com', 'registry.yarnpkg.com'],
        ports: [443, 80],
      },
      // PyPI
      {
        allow: ['pypi.org', '*.pypi.org', 'files.pythonhosted.org'],
        ports: [443, 80],
      },
      // Cargo registry
      {
        allow: ['crates.io', '*.crates.io', 'static.crates.io', 'index.crates.io'],
        ports: [443, 80],
      },
      // Go module proxy
      {
        allow: ['proxy.golang.org', 'sum.golang.org', '*.golang.org'],
        ports: [443, 80],
      },
      // Other registries (Maven, RubyGems, Docker, Homebrew)
      {
        allow: [
          'repo1.maven.org', 'central.maven.org', '*.maven.org',
          'rubygems.org', '*.rubygems.org',
          'registry-1.docker.io', '*.docker.io', '*.docker.com',
          'ghcr.io', '*.ghcr.io',
          'formulae.brew.sh',
        ],
        ports: [443, 80],
      },
      // GitHub (HTTPS + SSH)
      {
        allow: ['github.com', '*.github.com', '*.githubusercontent.com', 'api.github.com'],
        ports: [443, 80, 22],
      },
      // GitLab
      { allow: ['gitlab.com', '*.gitlab.com'], ports: [443, 80, 22] },
      // Bitbucket
      { allow: ['bitbucket.org', '*.bitbucket.org'], ports: [443, 80, 22] },
      // CDNs
      {
        allow: ['*.cloudflare.com', '*.cloudfront.net', 'cdn.jsdelivr.net', 'unpkg.com', 'esm.sh'],
        ports: [443, 80],
      },
      // Localhost
      { allowCidrs: ['127.0.0.1/32', '::1/128'] },
      // Block cloud metadata services
      { denyCidrs: ['169.254.169.254/32', '100.100.100.200/32'] },
      // Block private networks
      { denyCidrs: ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '169.254.0.0/16'] },
      // Default deny
      { deny: '*' },
    ],
    commands: [
      // File operations
      {
        allow: [
          'ls', 'cat', 'head', 'tail', 'less', 'more', 'file', 'stat',
          'wc', 'du', 'df', 'touch', 'mkdir', 'cp', 'mv', 'ln',
          'chmod', 'rm', 'rmdir', 'basename', 'dirname', 'realpath', 'readlink',
        ],
      },
      // Search tools
      {
        allow: [
          'grep', 'rg', 'find', 'fd', 'ag', 'ack',
          'which', 'whereis', 'type', 'locate',
        ],
      },
      // Text processing
      {
        allow: [
          'sed', 'awk', 'tr', 'sort', 'uniq', 'cut', 'paste',
          'tee', 'xargs', 'jq', 'yq', 'column', 'fmt', 'fold',
          'expand', 'unexpand',
        ],
      },
      // Shell interpreters and builtins
      {
        allow: [
          'bash', 'sh', 'zsh', '/bin/bash', '/bin/sh',
          'env', 'printenv', 'true', 'false', 'test', '[',
          'expr', 'seq', 'sh.real', 'bash.real',
        ],
      },
      // System information
      {
        allow: [
          'whoami', 'id', 'uname', 'hostname', 'pwd', 'date',
          'echo', 'printf', 'yes', 'sleep', 'time', 'timeout',
        ],
      },
      // Dev tools and runtimes
      {
        allow: [
          'git', 'node', 'npm', 'npx', 'yarn', 'pnpm', 'bun', 'deno',
          'python', 'python3', 'pip', 'pip3', 'uv',
          'go', 'cargo', 'rustc', 'rustup',
          'make', 'cmake', 'gcc', 'g++', 'clang', 'clang++', 'ld', 'ar',
          'javac', 'java', 'mvn', 'gradle',
          'ruby', 'gem', 'bundler',
          'php', 'composer',
        ],
      },
      // Build, test, and lint
      {
        allow: [
          'pytest', 'jest', 'mocha', 'vitest',
          'tsc', 'eslint', 'prettier',
          'rubocop', 'rspec', 'phpunit',
        ],
      },
      // HTTP tools (network rules are the real guard)
      { allow: ['curl', 'wget'] },
      // Containers
      { allow: ['docker', 'docker-compose', 'podman'] },
      // Archive and compression
      { allow: ['tar', 'gzip', 'gunzip', 'zip', 'unzip', 'bzip2', 'xz'] },
      // Miscellaneous utilities
      {
        allow: [
          'nohup', 'patch', 'diff', 'bc', 'openssl', 'ssh-keygen',
          'base64', 'md5sum', 'sha256sum',
          'ps', 'top', 'htop', 'pgrep',
        ],
      },
      // AI coding tools
      {
        allow: [
          'claude', 'codex', 'aider', 'copilot', 'gh',
          'agentsh', 'agentsh-unixwrap', 'agentsh-stub',
        ],
      },
      // Deny raw network tools
      { deny: ['nc', 'ncat', 'netcat', 'socat', 'telnet'] },
      // Deny system administration
      { deny: ['shutdown', 'reboot', 'halt', 'poweroff', 'systemctl', 'service', 'mount', 'umount', 'dd', 'fdisk', 'mkfs'] },
      // Deny privilege escalation
      { deny: ['sudo', 'su', 'doas', 'chroot', 'nsenter', 'unshare'] },
      // Deny system package managers (use language-specific managers)
      { deny: ['apt', 'apt-get', 'yum', 'dnf', 'brew'] },
      // Allow-all catch-all (file + network rules are the real enforcement)
      { allow: '*' },
    ],
    packageRules: [
      // Critical vulnerability = block
      {
        match: { findingType: 'vulnerability', severity: 'critical' },
        action: 'block',
        reason: 'Critical vulnerability — review before installing',
      },
      // Known malware = block
      {
        match: { findingType: 'malware' },
        action: 'block',
        reason: 'Known malware detected',
      },
      // Typosquat = block
      {
        match: { findingType: 'reputation', reasons: ['typosquat'] },
        action: 'block',
        reason: 'Package flagged as potential typosquat',
      },
      // Medium vulnerability = warn
      {
        match: { findingType: 'vulnerability', severity: 'medium' },
        action: 'warn',
        reason: 'Medium vulnerability — review before using',
      },
      // Copyleft licenses = block
      {
        match: {
          findingType: 'license',
          licenseSpdx: { deny: ['AGPL-3.0-only', 'SSPL-1.0'] },
        },
        action: 'block',
        reason: 'Copyleft license incompatible with proprietary code',
      },
      // Package too new = approve (requires human confirmation)
      {
        match: {
          findingType: 'reputation',
          reasons: ['package_too_new'],
        },
        action: 'approve',
        reason: 'Package published recently — requires approval',
      },
    ],
    envPolicy: {
      deny: [
        '*_SECRET*',
        '*_PASSWORD*',
        '*_PRIVATE_KEY*',
        '*_API_KEY*',
        '*_ACCESS_KEY*',
        '*_TOKEN',
        'ANTHROPIC_API_KEY',
        'OPENAI_API_KEY',
        'GITHUB_TOKEN',
        'GH_TOKEN',
        'NPM_TOKEN',
        'AWS_SECRET_ACCESS_KEY',
        'AWS_SESSION_TOKEN',
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
      { name: 'allow-docker-socket', paths: ['/var/run/docker.sock'], operations: ['connect'], decision: 'allow' },
      { name: 'deny-system-sockets', paths: ['/var/run/**'], operations: ['connect', 'bind', 'listen', 'sendto'], decision: 'deny' },
    ],
    resourceLimits: {
      maxMemoryMb: 8192,
      cpuQuotaPercent: 100,
      pidsMax: 500,
      commandTimeout: '15m',
      sessionTimeout: '12h',
      idleTimeout: '30m',
    },
    auditSettings: {
      logAllowed: false,
      logDenied: true,
      logApproved: true,
      includeStdout: false,
      includeStderr: true,
    },
  };
  return extensions ? merge(base, extensions) : base;
}

// ─── devSafe ───────────────────────────────────────────────

/**
 * Permissive defaults for local development. Not recommended for production.
 */
export function devSafe(
  extensions?: Partial<PolicyDefinition>,
): PolicyDefinition {
  const base: PolicyDefinition = {
    file: [
      { allow: '/workspace/**', ops: ['read', 'write', 'create'] },
      { deny: ['**/.env', '**/.env.*', '**/credentials*', '**/*.pem', '**/*.key'] },
      { deny: ['~/.ssh/**', '/proc/*/environ'] },
      { deny: ['~/.aws/**', '~/.gcp/**', '~/.azure/**', '~/.config/gcloud/**'] },
      { deny: ['~/.bashrc', '~/.zshrc', '~/.profile', '~/.bash_profile'] },
      { deny: ['~/.gitconfig', '~/.netrc', '~/.curlrc', '~/.wgetrc'] },
    ],
    network: [
      {
        allow: ['registry.npmjs.org', 'registry.yarnpkg.com'],
        ports: [443],
      },
    ],
    commands: [{ deny: ['env', 'printenv', 'shutdown', 'reboot'] }],
  };
  return extensions ? merge(base, extensions) : base;
}

// ─── ciStrict ──────────────────────────────────────────────

/**
 * Locked down for CI/CD runners.
 */
export function ciStrict(
  extensions?: Partial<PolicyDefinition>,
): PolicyDefinition {
  const base: PolicyDefinition = {
    file: [
      { allow: '/workspace/**' },
      { deny: ['**/.env', '**/.env.*', '**/credentials*', '**/*.pem', '**/*.key'] },
      { deny: ['~/.aws/**', '~/.gcp/**', '~/.azure/**', '~/.config/gcloud/**'] },
      { deny: '/**' },
    ],
    network: [
      {
        allow: [
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
        ports: [443],
      },
      { deny: '*' },
    ],
    commands: [
      { deny: ['env', 'printenv', 'shutdown', 'reboot', 'sudo'] },
    ],
  };
  return extensions ? merge(base, extensions) : base;
}

// ─── agentSandbox ──────────────────────────────────────────

/**
 * Maximum restriction for untrusted code. Read-only workspace, no network.
 */
export function agentSandbox(
  extensions?: Partial<PolicyDefinition>,
): PolicyDefinition {
  const base: PolicyDefinition = {
    file: [
      { allow: '/workspace/**', ops: ['read'] },
      { deny: '/**' },
    ],
    network: [{ deny: '*' }],
    commands: [
      { deny: ['env', 'printenv', 'sudo', 'su', 'shutdown', 'reboot'] },
    ],
  };
  return extensions ? merge(base, extensions) : base;
}
