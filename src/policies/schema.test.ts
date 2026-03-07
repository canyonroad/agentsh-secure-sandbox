import { describe, it, expect } from 'vitest';
import { PolicyDefinitionSchema, validatePolicy } from './schema.js';
import { PolicyValidationError } from '../core/errors.js';

describe('PolicyDefinitionSchema', () => {
  // File rules
  it('accepts valid file allow rule', () => {
    const result = PolicyDefinitionSchema.safeParse({
      file: [{ allow: '/workspace/**', ops: ['read', 'write'] }],
    });
    expect(result.success).toBe(true);
  });

  it('accepts file deny rule with string array', () => {
    const result = PolicyDefinitionSchema.safeParse({
      file: [{ deny: ['**/.env', '~/.ssh/**'] }],
    });
    expect(result.success).toBe(true);
  });

  it('accepts file deny rule with single string', () => {
    const result = PolicyDefinitionSchema.safeParse({
      file: [{ deny: '**/.env' }],
    });
    expect(result.success).toBe(true);
  });

  it('accepts file redirect rule', () => {
    const result = PolicyDefinitionSchema.safeParse({
      file: [{ redirect: '/secret', to: '/dev/null', ops: ['read'] }],
    });
    expect(result.success).toBe(true);
  });

  it('accepts file audit rule', () => {
    const result = PolicyDefinitionSchema.safeParse({
      file: [{ audit: '/workspace/**', ops: ['write'] }],
    });
    expect(result.success).toBe(true);
  });

  it('accepts file softDelete rule', () => {
    const result = PolicyDefinitionSchema.safeParse({
      file: [{ softDelete: '/workspace/tmp/**' }],
    });
    expect(result.success).toBe(true);
  });

  // Network rules
  it('accepts network allow with ports', () => {
    const result = PolicyDefinitionSchema.safeParse({
      network: [{ allow: ['registry.npmjs.org'], ports: [443] }],
    });
    expect(result.success).toBe(true);
  });

  it('accepts network deny wildcard', () => {
    const result = PolicyDefinitionSchema.safeParse({
      network: [{ deny: '*' }],
    });
    expect(result.success).toBe(true);
  });

  it('accepts network redirect rule', () => {
    const result = PolicyDefinitionSchema.safeParse({
      network: [{ redirect: 'prod.api.com', to: 'localhost:8080' }],
    });
    expect(result.success).toBe(true);
  });

  // Command rules
  it('accepts command allow rule', () => {
    const result = PolicyDefinitionSchema.safeParse({
      commands: [{ allow: ['node', 'npm'] }],
    });
    expect(result.success).toBe(true);
  });

  it('accepts command deny list', () => {
    const result = PolicyDefinitionSchema.safeParse({
      commands: [{ deny: ['env', 'printenv'] }],
    });
    expect(result.success).toBe(true);
  });

  it('accepts command redirect with string target', () => {
    const result = PolicyDefinitionSchema.safeParse({
      commands: [{ redirect: 'curl', to: '/usr/local/bin/safe-curl' }],
    });
    expect(result.success).toBe(true);
  });

  it('accepts command redirect with object target', () => {
    const result = PolicyDefinitionSchema.safeParse({
      commands: [{ redirect: ['curl', 'wget'], to: { cmd: 'agentsh-fetch', args: ['--audit'] } }],
    });
    expect(result.success).toBe(true);
  });

  // Env rules
  it('accepts env rules', () => {
    const result = PolicyDefinitionSchema.safeParse({
      env: [{ commands: ['node'], allow: ['PATH', 'HOME'] }],
    });
    expect(result.success).toBe(true);
  });

  it('accepts env rules with deny', () => {
    const result = PolicyDefinitionSchema.safeParse({
      env: [{ commands: ['node'], deny: ['SECRET_KEY'] }],
    });
    expect(result.success).toBe(true);
  });

  // DNS/Connect redirects
  it('accepts dns redirects', () => {
    const result = PolicyDefinitionSchema.safeParse({
      dns: [{ match: '.*\\.example\\.com', resolveTo: '127.0.0.1' }],
    });
    expect(result.success).toBe(true);
  });

  it('accepts connect redirects', () => {
    const result = PolicyDefinitionSchema.safeParse({
      connect: [{ match: 'api.prod.com:443', redirectTo: 'localhost:8080' }],
    });
    expect(result.success).toBe(true);
  });

  // Empty / full policy
  it('accepts empty policy', () => {
    const result = PolicyDefinitionSchema.safeParse({});
    expect(result.success).toBe(true);
  });

  it('accepts full agentDefault-style policy', () => {
    const result = PolicyDefinitionSchema.safeParse({
      file: [
        { allow: '/workspace/**', ops: ['read', 'write', 'create'] },
        { deny: ['/workspace/.git/config', '/workspace/.netrc'] },
        { deny: ['**/.env', '**/.env.*', '**/credentials*', '~/.ssh/**'] },
        { deny: '/proc/*/environ' },
      ],
      network: [
        { allow: ['registry.npmjs.org', 'registry.yarnpkg.com', 'pypi.org', 'files.pythonhosted.org'], ports: [443] },
        { deny: '*' },
      ],
      commands: [
        { deny: ['env', 'printenv', 'sudo', 'su', 'doas'] },
        { deny: ['shutdown', 'reboot', 'halt', 'poweroff'] },
        { deny: ['nc', 'ncat', 'netcat', 'socat', 'telnet'] },
        { deny: ['git push --force', 'git reset --hard'] },
        { redirect: ['curl', 'wget'], to: { cmd: 'agentsh-fetch', args: ['--audit'] } },
      ],
    });
    expect(result.success).toBe(true);
  });

  // Rejections
  it('rejects invalid file op', () => {
    const result = PolicyDefinitionSchema.safeParse({
      file: [{ allow: '/workspace/**', ops: ['execute'] }],
    });
    expect(result.success).toBe(false);
  });

  it('rejects file rule with no decision key', () => {
    const result = PolicyDefinitionSchema.safeParse({
      file: [{ paths: '/workspace/**' }],
    });
    expect(result.success).toBe(false);
  });

  it('rejects unknown top-level key', () => {
    const result = PolicyDefinitionSchema.safeParse({
      file: [{ allow: '/workspace/**' }],
      unknown: 'field',
    });
    expect(result.success).toBe(false);
  });
});

describe('validatePolicy', () => {
  it('returns valid policy', () => {
    const policy = validatePolicy({ file: [{ allow: '/workspace/**' }] });
    expect(policy.file).toHaveLength(1);
  });

  it('throws PolicyValidationError on invalid input', () => {
    expect(() => validatePolicy({ file: [{ invalid: true }] })).toThrow(PolicyValidationError);
  });
});
