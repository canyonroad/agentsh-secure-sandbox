import type { PolicyDefinition } from './schema.js';
import { merge } from './merge.js';

// ─── agentDefault ──────────────────────────────────────────

/**
 * Comprehensive policy for AI coding agents. This is the DEFAULT policy
 * used when no policy is specified. Aligned with production policies from
 * agentsh-vercel, e2b-agentsh, agentsh-cloudflare, agentsh-blaxel, and
 * daytona-test repos. Designed to work with all enforcement modes
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

      // --- System read (libraries, binaries) ---
      { allow: ['/usr/**', '/lib/**', '/lib64/**', '/bin/**', '/sbin/**'], ops: ['read', 'open', 'stat', 'list', 'readlink'] },

      // --- Sensitive /etc files (deny before /etc read) ---
      { deny: ['/etc/shadow', '/etc/gshadow', '/etc/sudoers', '/etc/sudoers.d/**'] },

      // --- /etc minimal read ---
      { allow: [
        '/etc/hosts', '/etc/resolv.conf',
        '/etc/ssl/**', '/etc/ca-certificates/**',
        '/etc/localtime', '/etc/timezone',
        '/etc/ld.so.cache', '/etc/ld.so.conf', '/etc/ld.so.conf.d/**',
        '/etc/nsswitch.conf', '/etc/passwd', '/etc/group',
        '/etc/mime.types', '/etc/protocols', '/etc/services',
      ], ops: ['read', 'open', 'stat', 'readlink'] },

      // --- Device files ---
      { allow: [
        '/dev/null', '/dev/zero', '/dev/urandom', '/dev/random',
        '/dev/stdin', '/dev/stdout', '/dev/stderr',
        '/dev/fd/**', '/dev/pts/**', '/dev/tty',
      ], ops: ['read', 'write', 'open', 'stat'] },

      // --- /proc/self for process introspection ---
      { allow: ['/proc/self/**', '/proc/thread-self/**'], ops: ['read', 'open', 'stat', 'list', 'readlink'] },

      // --- Package caches (read-only) ---
      { allow: [
        '~/.npm/**', '~/.cache/**', '~/.cargo/**',
        '/root/.npm/**', '/root/.cache/**', '/root/.cargo/**',
      ], ops: ['read', 'open', 'stat', 'list'] },

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

      // --- Block /proc and /sys (except /proc/self already allowed above) ---
      { deny: ['/proc/**', '/sys/**'] },

      // --- Default deny (catch-all) ---
      { deny: '**' },
    ],
    network: [
      // Localhost
      { allowCidrs: ['127.0.0.1/32', '::1/128'] },
      // Package registries + code hosting
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
          'github.com',
          'raw.githubusercontent.com',
        ],
        ports: [443],
      },
      // Block cloud metadata services
      { denyCidrs: ['169.254.169.254/32', '100.100.100.200/32'] },
      // Block private networks
      { denyCidrs: ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '169.254.0.0/16'] },
      // Default deny
      { deny: '*' },
    ],
    commands: [
      // Allow safe commands
      {
        allow: [
          'bash', 'sh', '/bin/bash', '/bin/sh',
          'echo', 'cat', 'head', 'tail', 'grep', 'find',
          'ls', 'wc', 'sort', 'uniq', 'diff', 'pwd', 'date', 'which',
          'whoami', 'id', 'uname', 'printf', 'test', 'true', 'false',
          'mkdir', 'cp', 'mv', 'rm', 'touch', 'chmod', 'tr', 'cut',
          'sed', 'awk', 'tee', 'xargs', 'basename', 'dirname', 'realpath',
          'base64', 'md5sum', 'sha256sum', 'tar', 'gzip', 'gunzip',
          'env', 'printenv', 'curl', 'wget',
        ],
      },
      // Allow dev tools
      {
        allow: [
          'git', 'node', 'npm', 'npx', 'yarn', 'pnpm', 'bun',
          'python', 'python3', 'pip', 'pip3',
          'cargo', 'rustc', 'go', 'make', 'cmake',
        ],
      },
      // Deny network tools
      { deny: ['nc', 'ncat', 'netcat', 'socat', 'telnet', 'ssh', 'scp', 'rsync'] },
      // Deny system commands
      { deny: ['shutdown', 'reboot', 'halt', 'poweroff', 'systemctl', 'service', 'mount', 'umount', 'dd', 'fdisk', 'mkfs', 'kill', 'killall', 'pkill'] },
      // Deny shell escapes
      { deny: ['sudo', 'su', 'doas', 'chroot', 'nsenter', 'unshare'] },
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
