import type { ZodIssue } from 'zod';

export class AgentSHError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'AgentSHError';
  }
}

export class PolicyValidationError extends AgentSHError {
  readonly issues: ZodIssue[];

  constructor({ issues }: { issues: ZodIssue[] }) {
    const summaries = issues
      .map((issue) => `${issue.path.join('.')}: ${issue.message}`)
      .join('; ');
    super(`Policy validation failed: ${summaries}`);
    this.name = 'PolicyValidationError';
    this.issues = issues;
  }
}

export class MissingPeerDependencyError extends AgentSHError {
  readonly packageName: string;
  readonly versionRange: string;

  constructor({
    packageName,
    versionRange,
  }: {
    packageName: string;
    versionRange: string;
  }) {
    super(
      `${packageName} is required but not installed. Run: npm install ${packageName}@"${versionRange}"`,
    );
    this.name = 'MissingPeerDependencyError';
    this.packageName = packageName;
    this.versionRange = versionRange;
  }
}

export class IncompatibleProviderVersionError extends AgentSHError {
  readonly installed: string;
  readonly required: string;
  readonly packageName: string;

  constructor({
    installed,
    required,
    packageName,
  }: {
    installed: string;
    required: string;
    packageName: string;
  }) {
    super(
      `${packageName} version ${installed} is not supported. @agentsh/secure-sandbox requires ${packageName} ${required}. Please upgrade: npm install ${packageName}@latest`,
    );
    this.name = 'IncompatibleProviderVersionError';
    this.installed = installed;
    this.required = required;
    this.packageName = packageName;
  }
}

export class ProvisioningError extends AgentSHError {
  readonly phase: string;
  readonly command: string;
  readonly stderr: string;

  constructor({
    phase,
    command,
    stderr,
  }: {
    phase: string;
    command: string;
    stderr: string;
  }) {
    super(`Provisioning failed at phase: ${phase}`);
    this.name = 'ProvisioningError';
    this.phase = phase;
    this.command = command;
    this.stderr = stderr;
  }
}

export class IntegrityError extends AgentSHError {
  readonly expected: string;
  readonly actual: string;

  constructor({
    expected,
    actual,
    message,
  }: {
    expected: string;
    actual: string;
    message?: string;
  }) {
    super(message ?? `Checksum mismatch: expected ${expected}, got ${actual}`);
    this.name = 'IntegrityError';
    this.expected = expected;
    this.actual = actual;
  }
}

export class RuntimeError extends AgentSHError {
  readonly sessionId: string;
  readonly command: string;
  readonly stderr: string;

  constructor({
    sessionId,
    command,
    stderr,
  }: {
    sessionId: string;
    command: string;
    stderr: string;
  }) {
    super(`agentsh exec failed (session ${sessionId})`);
    this.name = 'RuntimeError';
    this.sessionId = sessionId;
    this.command = command;
    this.stderr = stderr;
  }
}
