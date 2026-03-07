import type { PolicyDefinition } from './schema.js';

// ─── Internal helper ───────────────────────────────────────

function applyExtensions(
  base: PolicyDefinition,
  extensions?: Partial<PolicyDefinition>,
): PolicyDefinition {
  if (!extensions) return base;
  const result = { ...base };
  const categories = ['file', 'network', 'commands', 'env', 'dns', 'connect'] as const;
  for (const key of categories) {
    if (extensions[key]) {
      result[key] = [...(base[key] ?? []), ...extensions[key]!] as any;
    }
  }
  return result;
}

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
      { deny: ['/workspace/.git/config', '/workspace/.netrc'] },
      { deny: ['**/.env', '**/.env.*', '**/credentials*', '~/.ssh/**'] },
      { deny: '/proc/*/environ' },
    ],
    network: [
      {
        allow: [
          'registry.npmjs.org',
          'registry.yarnpkg.com',
          'pypi.org',
          'files.pythonhosted.org',
        ],
        ports: [443],
      },
      { deny: '*' },
    ],
    commands: [
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
  return applyExtensions(base, extensions);
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
      { deny: ['**/.env', '**/.env.*', '**/credentials*', '~/.ssh/**'] },
      { deny: '/proc/*/environ' },
    ],
    network: [
      {
        allow: ['registry.npmjs.org', 'registry.yarnpkg.com'],
        ports: [443],
      },
    ],
    commands: [{ deny: ['env', 'printenv', 'shutdown', 'reboot'] }],
  };
  return applyExtensions(base, extensions);
}

// ─── ciStrict ──────────────────────────────────────────────

/**
 * Locked down for CI/CD runners.
 */
export function ciStrict(
  extensions?: Partial<PolicyDefinition>,
): PolicyDefinition {
  const base: PolicyDefinition = {
    file: [{ allow: '/workspace/**' }, { deny: '/**' }],
    network: [
      {
        allow: ['registry.npmjs.org', 'registry.yarnpkg.com'],
        ports: [443],
      },
      { deny: '*' },
    ],
    commands: [
      { deny: ['env', 'printenv', 'shutdown', 'reboot', 'sudo'] },
    ],
  };
  return applyExtensions(base, extensions);
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
  return applyExtensions(base, extensions);
}
