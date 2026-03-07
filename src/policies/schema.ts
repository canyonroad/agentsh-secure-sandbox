import { z, ZodError } from 'zod';
import { PolicyValidationError } from '../core/errors.js';

// ─── Shared helpers ─────────────────────────────────────────

const stringOrArray = z.union([z.string(), z.array(z.string())]);

// ─── File rules ─────────────────────────────────────────────

export const FileOpSchema = z.enum(['read', 'write', 'create', 'delete']);

const FileAllowRule = z
  .object({ allow: stringOrArray, ops: z.array(FileOpSchema).optional() })
  .strict();

const FileDenyRule = z.object({ deny: stringOrArray }).strict();

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
    ports: z.array(z.number().int().positive()).optional(),
  })
  .strict();

const NetworkDenyRule = z.object({ deny: stringOrArray }).strict();

const NetworkRedirectRule = z
  .object({ redirect: z.string(), to: z.string() })
  .strict();

export const NetworkRuleSchema = z.union([
  NetworkAllowRule,
  NetworkDenyRule,
  NetworkRedirectRule,
]);

// ─── Command rules ──────────────────────────────────────────

const CommandRedirectTarget = z.union([
  z.string(),
  z.object({ cmd: z.string(), args: z.array(z.string()) }),
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

// ─── PolicyDefinition ───────────────────────────────────────

export const PolicyDefinitionSchema = z
  .object({
    file: z.array(FileRuleSchema).optional(),
    network: z.array(NetworkRuleSchema).optional(),
    commands: z.array(CommandRuleSchema).optional(),
    env: z.array(EnvRuleSchema).optional(),
    dns: z.array(DnsRedirectSchema).optional(),
    connect: z.array(ConnectRedirectSchema).optional(),
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
