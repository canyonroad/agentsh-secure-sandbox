import type { PolicyDefinition } from './schema.js';
import { merge } from './merge.js';

// ─── agentDefault ──────────────────────────────────────────

/**
 * Comprehensive policy for AI coding agents. This is the DEFAULT policy
 * used when no policy is specified. Based on agentsh v0.13's agent-default
 * policy.
 */
export function agentDefault(
  extensions?: Partial<PolicyDefinition>,
): PolicyDefinition {
  const base: PolicyDefinition = {
    file: [
      { allow: '/workspace/**', ops: ['read', 'write', 'create'] },
      // Git/version-control credentials
      { deny: ['/workspace/.git/config', '/workspace/.netrc'] },
      // Secrets and credentials
      { deny: ['**/.env', '**/.env.*', '**/credentials*', '**/*.pem', '**/*.key'] },
      { deny: ['~/.ssh/**', '/proc/*/environ'] },
      // Cloud provider credentials
      { deny: ['~/.aws/**', '~/.gcp/**', '~/.azure/**', '~/.config/gcloud/**'] },
      // Shell config injection (persistence)
      { deny: ['~/.bashrc', '~/.zshrc', '~/.profile', '~/.bash_profile'] },
      // Credential stores
      { deny: ['~/.gitconfig', '~/.netrc', '~/.curlrc', '~/.wgetrc'] },
      // PATH hijacking
      { deny: '~/.local/bin/**' },
      // Agent config files (prompt injection)
      { deny: ['**/.cursorrules', '**/CLAUDE.md', '**/copilot-instructions.md'] },
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
          'github.com',
          'raw.githubusercontent.com',
        ],
        ports: [443],
      },
      { deny: '*' },
    ],
    commands: [
      // Allow safe commands (order matters — first match wins)
      {
        allow: [
          'bash', 'sh', 'echo', 'cat', 'head', 'tail', 'grep', 'find',
          'ls', 'wc', 'sort', 'uniq', 'diff', 'pwd', 'date', 'which',
          'whoami', 'id', 'uname', 'printf', 'test', 'true', 'false',
          'mkdir', 'cp', 'mv', 'rm', 'touch', 'chmod', 'tr', 'cut',
          'sed', 'awk', 'tee', 'xargs', 'basename', 'dirname', 'realpath',
          'base64', 'md5sum', 'sha256sum', 'tar', 'gzip', 'gunzip',
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
      // Deny dangerous commands
      { deny: ['env', 'printenv', 'sudo', 'su', 'doas'] },
      { deny: ['shutdown', 'reboot', 'halt', 'poweroff'] },
      { deny: ['nc', 'ncat', 'netcat', 'socat', 'telnet'] },
      { deny: ['git push --force', 'git reset --hard'] },
      {
        redirect: ['curl', 'wget'],
        to: { cmd: 'agentsh-fetch', args: ['--audit'] },
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
          'proxy.golang.org',
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
