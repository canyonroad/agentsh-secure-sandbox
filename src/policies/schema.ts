import { z, ZodError } from 'zod';
import { PolicyValidationError } from '../core/errors.js';

// ─── Shared helpers ─────────────────────────────────────────

const stringOrArray = z.union([z.string(), z.array(z.string())]);

// ─── File rules ─────────────────────────────────────────────

export const FileOpSchema = z.string();

const FileAllowRule = z
  .object({ allow: stringOrArray, ops: z.array(FileOpSchema).optional() })
  .strict();

const FileDenyRule = z
  .object({ deny: stringOrArray, ops: z.array(FileOpSchema).optional() })
  .strict();

const FileRedirectRule = z
  .object({
    redirect: stringOrArray,
    to: z.string(),
    ops: z.array(FileOpSchema).optional(),
  })
  .strict();

const FileAuditRule = z
  .object({ audit: stringOrArray, ops: z.array(FileOpSchema).optional() })
  .strict();

const FileSoftDeleteRule = z.object({ softDelete: stringOrArray }).strict();

export const FileRuleSchema = z.union([
  FileAllowRule,
  FileDenyRule,
  FileRedirectRule,
  FileAuditRule,
  FileSoftDeleteRule,
]);

// ─── Network rules ──────────────────────────────────────────

const NetworkAllowRule = z
  .object({
    allow: stringOrArray,
    ports: z.array(z.number().int().min(1).max(65535)).optional(),
  })
  .strict();

const NetworkDenyRule = z.object({ deny: stringOrArray }).strict();

const NetworkRedirectRule = z
  .object({ redirect: z.string(), to: z.string() })
  .strict();

const NetworkAllowCidrsRule = z
  .object({
    allowCidrs: z.array(z.string()),
    ports: z.array(z.number().int().min(1).max(65535)).optional(),
  })
  .strict();

const NetworkDenyCidrsRule = z
  .object({
    denyCidrs: z.array(z.string()),
  })
  .strict();

export const NetworkRuleSchema = z.union([
  NetworkAllowRule,
  NetworkDenyRule,
  NetworkRedirectRule,
  NetworkAllowCidrsRule,
  NetworkDenyCidrsRule,
]);

// ─── Command rules ──────────────────────────────────────────

const CommandRedirectTarget = z.union([
  z.string(),
  z.object({ cmd: z.string(), args: z.array(z.string()) }).strict(),
]);

const CommandAllowRule = z.object({ allow: stringOrArray }).strict();

const CommandDenyRule = z.object({ deny: stringOrArray }).strict();

const CommandRedirectRule = z
  .object({ redirect: stringOrArray, to: CommandRedirectTarget })
  .strict();

export const CommandRuleSchema = z.union([
  CommandAllowRule,
  CommandDenyRule,
  CommandRedirectRule,
]);

// ─── Env rules ──────────────────────────────────────────────

export const EnvRuleSchema = z
  .object({
    commands: z.array(z.string()),
    allow: z.array(z.string()).optional(),
    deny: z.array(z.string()).optional(),
  })
  .strict();

// ─── DNS / Connect redirects ────────────────────────────────

export const DnsRedirectSchema = z
  .object({
    match: z.string(),
    resolveTo: z.string(),
  })
  .strict();

export const ConnectRedirectSchema = z
  .object({
    match: z.string(),
    redirectTo: z.string(),
  })
  .strict();

// ─── Package rules ──────────────────────────────────────────

const LicenseSpdxMatchSchema = z
  .object({
    allow: z.array(z.string()).optional(),
    deny: z.array(z.string()).optional(),
  })
  .strict();

const PackageMatchSchema = z
  .object({
    packages: z.array(z.string()).optional(),
    namePatterns: z.array(z.string()).optional(),
    findingType: z.string().optional(),
    severity: stringOrArray.optional(),
    reasons: z.array(z.string()).optional(),
    licenseSpdx: LicenseSpdxMatchSchema.optional(),
    ecosystem: z.string().optional(),
    options: z.record(z.unknown()).optional(),
  })
  .strict();

export const PackageRuleSchema = z
  .object({
    match: PackageMatchSchema,
    action: z.enum(['allow', 'warn', 'approve', 'block']),
    reason: z.string().optional(),
  })
  .strict();

// ─── Env policy (top-level, distinct from per-command env rules) ─

export const EnvPolicySchema = z
  .object({
    allow: z.array(z.string()).optional(),
    deny: z.array(z.string()).optional(),
    maxBytes: z.number().int().optional(),
    maxKeys: z.number().int().optional(),
    blockIteration: z.boolean().optional(),
  })
  .strict();

// ─── Signal rules ──────────────────────────────────────────

const SignalTargetSchema = z
  .object({
    type: z.enum(['self', 'children', 'session', 'parent', 'external', 'system']),
    pattern: z.string().optional(),
  })
  .strict();

export const SignalRuleSchema = z
  .object({
    name: z.string(),
    signals: z.array(z.string()),
    target: SignalTargetSchema,
    decision: z.enum(['allow', 'deny', 'audit']),
    fallback: z.string().optional(),
    message: z.string().optional(),
  })
  .strict();

// ─── Unix socket rules ────────────────────────────────────

export const UnixSocketRuleSchema = z
  .object({
    name: z.string(),
    paths: z.array(z.string()),
    operations: z.array(z.string()).optional(),
    decision: z.enum(['allow', 'deny']),
    message: z.string().optional(),
  })
  .strict();

// ─── Secret providers ────────────────────────────────────

const VaultAuthSchema = z
  .object({
    method: z.enum(['token', 'approle', 'kubernetes']).optional(),
    token: z.string().optional(),
    tokenRef: z.string().optional(),
    roleId: z.string().optional(),
    roleIdRef: z.string().optional(),
    secretId: z.string().optional(),
    secretIdRef: z.string().optional(),
    kubeRole: z.string().optional(),
    kubeMountPath: z.string().optional(),
    kubeTokenPath: z.string().optional(),
  })
  .strict();

export const SecretProviderSchema = z.discriminatedUnion('type', [
  z.object({ type: z.literal('keyring') }).strict(),
  z.object({
    type: z.literal('vault'),
    address: z.string(),
    namespace: z.string().optional(),
    auth: VaultAuthSchema.optional(),
  }).strict(),
  z.object({ type: z.literal('aws-sm'), region: z.string() }).strict(),
  z.object({ type: z.literal('gcp-sm'), projectId: z.string() }).strict(),
  z.object({ type: z.literal('azure-kv'), vaultUrl: z.string() }).strict(),
  z.object({
    type: z.literal('op'),
    serverUrl: z.string(),
    apiKey: z.string().optional(),
    apiKeyRef: z.string().optional(),
  }).strict(),
]);

// ─── Resource limits ───────────────────────────────────────

export const ResourceLimitsSchema = z
  .object({
    maxMemoryMb: z.number().int().optional(),
    cpuQuotaPercent: z.number().int().optional(),
    pidsMax: z.number().int().optional(),
    commandTimeout: z.string().optional(),
    sessionTimeout: z.string().optional(),
    idleTimeout: z.string().optional(),
  })
  .strict();

// ─── Audit settings ────────────────────────────────────────

export const AuditSettingsSchema = z
  .object({
    logAllowed: z.boolean().optional(),
    logDenied: z.boolean().optional(),
    logApproved: z.boolean().optional(),
    includeStdout: z.boolean().optional(),
    includeStderr: z.boolean().optional(),
  })
  .strict();

// ─── PolicyDefinition ───────────────────────────────────────

export const PolicyDefinitionSchema = z
  .object({
    file: z.array(FileRuleSchema).optional(),
    network: z.array(NetworkRuleSchema).optional(),
    commands: z.array(CommandRuleSchema).optional(),
    env: z.array(EnvRuleSchema).optional(),
    dns: z.array(DnsRedirectSchema).optional(),
    connect: z.array(ConnectRedirectSchema).optional(),
    packageRules: z.array(PackageRuleSchema).optional(),
    envPolicy: EnvPolicySchema.optional(),
    signalRules: z.array(SignalRuleSchema).optional(),
    unixSocketRules: z.array(UnixSocketRuleSchema).optional(),
    resourceLimits: ResourceLimitsSchema.optional(),
    auditSettings: AuditSettingsSchema.optional(),
    providers: z.record(z.string(), SecretProviderSchema).optional(),
  })
  .strict();

// ─── Inferred types ─────────────────────────────────────────

export type PolicyDefinition = z.infer<typeof PolicyDefinitionSchema>;
export type FileOp = z.infer<typeof FileOpSchema>;
export type FileRule = z.infer<typeof FileRuleSchema>;
export type NetworkRule = z.infer<typeof NetworkRuleSchema>;
export type CommandRule = z.infer<typeof CommandRuleSchema>;
export type EnvRule = z.infer<typeof EnvRuleSchema>;
export type DnsRedirect = z.infer<typeof DnsRedirectSchema>;
export type ConnectRedirect = z.infer<typeof ConnectRedirectSchema>;
export type PackageRule = z.infer<typeof PackageRuleSchema>;
export type EnvPolicy = z.infer<typeof EnvPolicySchema>;
export type SignalRule = z.infer<typeof SignalRuleSchema>;
export type UnixSocketRule = z.infer<typeof UnixSocketRuleSchema>;
export type ResourceLimits = z.infer<typeof ResourceLimitsSchema>;
export type AuditSettings = z.infer<typeof AuditSettingsSchema>;
export type VaultAuth = z.infer<typeof VaultAuthSchema>;
export type SecretProvider = z.infer<typeof SecretProviderSchema>;

// ─── Validation ─────────────────────────────────────────────

export function validatePolicy(policy: unknown): PolicyDefinition {
  try {
    return PolicyDefinitionSchema.parse(policy);
  } catch (err) {
    if (err instanceof ZodError) {
      throw new PolicyValidationError({ issues: err.issues });
    }
    throw err;
  }
}
