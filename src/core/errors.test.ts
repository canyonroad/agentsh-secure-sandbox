import { describe, it, expect } from 'vitest';
import {
  AgentSHError,
  PolicyValidationError,
  MissingPeerDependencyError,
  IncompatibleProviderVersionError,
  ProvisioningError,
  IntegrityError,
  RuntimeError,
} from './errors.js';

describe('AgentSHError', () => {
  it('extends Error', () => {
    const err = new AgentSHError('test message');
    expect(err).toBeInstanceOf(Error);
    expect(err).toBeInstanceOf(AgentSHError);
  });

  it('sets name to AgentSHError', () => {
    const err = new AgentSHError('test');
    expect(err.name).toBe('AgentSHError');
  });

  it('sets message', () => {
    const err = new AgentSHError('something went wrong');
    expect(err.message).toBe('something went wrong');
  });
});

describe('PolicyValidationError', () => {
  const issues = [
    {
      code: 'invalid_type' as const,
      expected: 'string',
      received: 'number',
      path: ['file', 0, 'allow'],
      message: 'Expected string, received number',
    },
  ];

  it('extends AgentSHError', () => {
    const err = new PolicyValidationError({ issues });
    expect(err).toBeInstanceOf(AgentSHError);
    expect(err).toBeInstanceOf(Error);
  });

  it('sets name to PolicyValidationError', () => {
    const err = new PolicyValidationError({ issues });
    expect(err.name).toBe('PolicyValidationError');
  });

  it('stores issues property', () => {
    const err = new PolicyValidationError({ issues });
    expect(err.issues).toBe(issues);
  });

  it('generates descriptive message', () => {
    const err = new PolicyValidationError({ issues });
    expect(err.message).toContain('Policy validation failed');
    expect(err.message).toContain('file.0.allow');
  });

  it('handles multiple issues in message', () => {
    const multiIssues = [
      {
        code: 'invalid_type' as const,
        expected: 'string',
        received: 'number',
        path: ['file', 0, 'allow'],
        message: 'Expected string, received number',
      },
      {
        code: 'invalid_type' as const,
        expected: 'array',
        received: 'string',
        path: ['network'],
        message: 'Expected array, received string',
      },
    ];
    const err = new PolicyValidationError({ issues: multiIssues });
    expect(err.message).toContain('file.0.allow');
    expect(err.message).toContain('network');
  });
});

describe('MissingPeerDependencyError', () => {
  it('extends AgentSHError', () => {
    const err = new MissingPeerDependencyError({
      packageName: '@vercel/sandbox',
      versionRange: '^1.0.0',
    });
    expect(err).toBeInstanceOf(AgentSHError);
    expect(err).toBeInstanceOf(Error);
  });

  it('sets name to MissingPeerDependencyError', () => {
    const err = new MissingPeerDependencyError({
      packageName: '@vercel/sandbox',
      versionRange: '^1.0.0',
    });
    expect(err.name).toBe('MissingPeerDependencyError');
  });

  it('stores properties', () => {
    const err = new MissingPeerDependencyError({
      packageName: '@vercel/sandbox',
      versionRange: '^1.0.0',
    });
    expect(err.packageName).toBe('@vercel/sandbox');
    expect(err.versionRange).toBe('^1.0.0');
  });

  it('generates correct message with quoted version range', () => {
    const err = new MissingPeerDependencyError({
      packageName: '@vercel/sandbox',
      versionRange: '^1.0.0',
    });
    expect(err.message).toBe(
      '@vercel/sandbox is required but not installed. Run: npm install @vercel/sandbox@"^1.0.0"',
    );
  });

  it('quotes version range containing || to prevent shell interpretation', () => {
    const err = new MissingPeerDependencyError({
      packageName: '@daytonaio/sdk',
      versionRange: '^0.12.0 || ^1.0.0',
    });
    expect(err.message).toContain('@"^0.12.0 || ^1.0.0"');
  });
});

describe('IncompatibleProviderVersionError', () => {
  it('extends AgentSHError', () => {
    const err = new IncompatibleProviderVersionError({
      installed: '0.10.3',
      required: '^0.12.0 || ^1.0.0',
      packageName: '@daytonaio/sdk',
    });
    expect(err).toBeInstanceOf(AgentSHError);
    expect(err).toBeInstanceOf(Error);
  });

  it('sets name to IncompatibleProviderVersionError', () => {
    const err = new IncompatibleProviderVersionError({
      installed: '0.10.3',
      required: '^0.12.0 || ^1.0.0',
      packageName: '@daytonaio/sdk',
    });
    expect(err.name).toBe('IncompatibleProviderVersionError');
  });

  it('stores properties', () => {
    const err = new IncompatibleProviderVersionError({
      installed: '0.10.3',
      required: '^0.12.0 || ^1.0.0',
      packageName: '@daytonaio/sdk',
    });
    expect(err.installed).toBe('0.10.3');
    expect(err.required).toBe('^0.12.0 || ^1.0.0');
    expect(err.packageName).toBe('@daytonaio/sdk');
  });

  it('generates message matching spec example format', () => {
    const err = new IncompatibleProviderVersionError({
      installed: '0.10.3',
      required: '^0.12.0 || ^1.0.0',
      packageName: '@daytonaio/sdk',
    });
    expect(err.message).toBe(
      '@daytonaio/sdk version 0.10.3 is not supported. @agentsh/secure-sandbox requires @daytonaio/sdk ^0.12.0 || ^1.0.0. Please upgrade: npm install @daytonaio/sdk@latest',
    );
  });
});

describe('ProvisioningError', () => {
  it('extends AgentSHError', () => {
    const err = new ProvisioningError({
      phase: 'install',
      command: 'curl -fsSL https://...',
      stderr: 'Connection refused',
    });
    expect(err).toBeInstanceOf(AgentSHError);
    expect(err).toBeInstanceOf(Error);
  });

  it('sets name to ProvisioningError', () => {
    const err = new ProvisioningError({
      phase: 'install',
      command: 'curl -fsSL https://...',
      stderr: 'Connection refused',
    });
    expect(err.name).toBe('ProvisioningError');
  });

  it('stores properties', () => {
    const err = new ProvisioningError({
      phase: 'startup',
      command: 'agentsh server start',
      stderr: 'port in use',
    });
    expect(err.phase).toBe('startup');
    expect(err.command).toBe('agentsh server start');
    expect(err.stderr).toBe('port in use');
  });

  it('generates generic message without raw command or stderr', () => {
    const err = new ProvisioningError({
      phase: 'install',
      command: 'curl -fsSL https://...',
      stderr: 'Connection refused',
    });
    expect(err.message).toBe('Provisioning failed at phase: install');
  });

  it('does not leak command or stderr in message', () => {
    const err = new ProvisioningError({
      phase: 'install',
      command: 'curl -H "Authorization: Bearer SECRET"',
      stderr: 'token=abc123',
    });
    expect(err.message).not.toContain('curl');
    expect(err.message).not.toContain('SECRET');
    expect(err.message).not.toContain('token=abc123');
    // but properties are still accessible
    expect(err.command).toBe('curl -H "Authorization: Bearer SECRET"');
    expect(err.stderr).toBe('token=abc123');
  });
});

describe('IntegrityError', () => {
  it('extends AgentSHError', () => {
    const err = new IntegrityError({
      expected: 'abc123',
      actual: 'def456',
    });
    expect(err).toBeInstanceOf(AgentSHError);
    expect(err).toBeInstanceOf(Error);
  });

  it('sets name to IntegrityError', () => {
    const err = new IntegrityError({
      expected: 'abc123',
      actual: 'def456',
    });
    expect(err.name).toBe('IntegrityError');
  });

  it('stores properties', () => {
    const err = new IntegrityError({
      expected: 'abc123',
      actual: 'def456',
    });
    expect(err.expected).toBe('abc123');
    expect(err.actual).toBe('def456');
  });

  it('generates default message when no custom message', () => {
    const err = new IntegrityError({
      expected: 'abc123',
      actual: 'def456',
    });
    expect(err.message).toBe('Checksum mismatch: expected abc123, got def456');
  });

  it('uses custom message when provided', () => {
    const err = new IntegrityError({
      expected: '',
      actual: '',
      message: 'No pinned checksum for agentsh v0.15.0. Provide `agentshChecksum` explicitly or use `skipIntegrityCheck: true`.',
    });
    expect(err.message).toBe(
      'No pinned checksum for agentsh v0.15.0. Provide `agentshChecksum` explicitly or use `skipIntegrityCheck: true`.',
    );
  });
});

describe('RuntimeError', () => {
  it('extends AgentSHError', () => {
    const err = new RuntimeError({
      sessionId: 'sess-abc123',
      command: 'ls /workspace',
      stderr: 'socket closed',
    });
    expect(err).toBeInstanceOf(AgentSHError);
    expect(err).toBeInstanceOf(Error);
  });

  it('sets name to RuntimeError', () => {
    const err = new RuntimeError({
      sessionId: 'sess-abc123',
      command: 'ls /workspace',
      stderr: 'socket closed',
    });
    expect(err.name).toBe('RuntimeError');
  });

  it('stores properties', () => {
    const err = new RuntimeError({
      sessionId: 'sess-abc123',
      command: 'ls /workspace',
      stderr: 'socket closed',
    });
    expect(err.sessionId).toBe('sess-abc123');
    expect(err.command).toBe('ls /workspace');
    expect(err.stderr).toBe('socket closed');
  });

  it('generates generic message without raw command or stderr', () => {
    const err = new RuntimeError({
      sessionId: 'sess-abc123',
      command: 'ls /workspace',
      stderr: 'socket closed',
    });
    expect(err.message).toBe('agentsh exec failed (session sess-abc123)');
  });

  it('does not leak command or stderr in message', () => {
    const err = new RuntimeError({
      sessionId: 'sess-xyz',
      command: 'cat /etc/shadow',
      stderr: 'permission denied for user root',
    });
    expect(err.message).not.toContain('cat /etc/shadow');
    expect(err.message).not.toContain('permission denied');
    // but properties are still accessible
    expect(err.command).toBe('cat /etc/shadow');
    expect(err.stderr).toBe('permission denied for user root');
  });
});
