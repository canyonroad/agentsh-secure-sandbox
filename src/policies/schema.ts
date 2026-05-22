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

// ─── HTTP services ───────────────────────────────────────

const HttpServiceSecretSchema = z
  .object({
    ref: z.string(),
    format: z.string(),
  })
  .strict();

const HttpServiceInjectHeaderSchema = z
  .object({
    name: z.string(),
    template: z.string(),
  })
  .strict();

const HttpServiceInjectSchema = z
  .object({
    header: HttpServiceInjectHeaderSchema.optional(),
  })
  .strict();

const HttpServiceRuleSchema = z
  .object({
    name: z.string(),
    methods: z.array(z.string()).optional(),
    paths: z.array(z.string()),
    decision: z.enum(['allow', 'deny', 'approve', 'audit']),
    message: z.string().optional(),
    timeout: z.string().optional(),
  })
  .strict();

export const HttpServiceSchema = z
  .object({
    name: z.string(),
    upstream: z.string(),
    exposeAs: z.string().optional(),
    aliases: z.array(z.string()).optional(),
    allowDirect: z.boolean().optional(),
    default: z.enum(['allow', 'deny']).optional(),
    rules: z.array(HttpServiceRuleSchema).optional(),
    secret: HttpServiceSecretSchema.optional(),
    inject: HttpServiceInjectSchema.optional(),
    scrubResponse: z.boolean().optional(),
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

// ─── DB access (v0.20+) ─────────────────────────────────────

const DbTlsMode = z.enum([
  'passthrough',
  'terminate_reissue',
  'terminate_plaintext_upstream',
]);

export const DbServiceDefSchema = z
  .object({
    family: z.string(),
    dialect: z.string(),
    upstream: z.string(),
    tlsMode: DbTlsMode,
    allowFunctionCallProtocol: z.boolean().optional(),
    allowGssEncryption: z.boolean().optional(),
    trustedNetwork: z.boolean().optional(),
  })
  .passthrough();

const DbDecision = z.enum([
  'allow',
  'deny',
  'approve',
  'audit',
  'redirect',
]);

const DbObjectResolution = z.enum([
  'qualified_syntactic',
  'unqualified_syntactic',
  'ambiguous_after_search_path',
  'maybe_temp_shadowed',
  'unresolved',
  'catalog_resolved',
  '*',
]);

const DbDenyModeInTx = z.enum(['terminate', 'rollback_then_continue']);

export const DatabaseRuleSchema = z
  .object({
    name: z.string(),
    dbService: z.string().optional(),
    dbFamily: z.string().optional(),
    dbDialect: z.string().optional(),
    schemas: z.array(z.string()).optional(),
    objects: z.array(z.string()).optional(),
    relations: z.array(z.string()).optional(),
    functions: z.array(z.string()).optional(),
    operations: z.array(z.string()),
    subtypes: z.array(z.string()).optional(),
    matchObjectResolution: DbObjectResolution.optional(),
    requireWhere: z.boolean().optional(),
    decision: DbDecision,
    message: z.string().optional(),
    timeout: z.string().optional(),
    redirect: z.object({ relation: z.string() }).optional(),
    acknowledgeAuditOnDangerous: z.boolean().optional(),
    denyModeInTx: DbDenyModeInTx.optional(),
  })
  .passthrough();

const DbConnectionDecision = z.enum(['allow', 'deny', 'approve', 'audit']);
const DbMatchKind = z.enum(['connect', 'cancel', 'replication']);

export const DatabaseConnectionRuleSchema = z
  .object({
    name: z.string(),
    dbService: z.string().optional(),
    matchKind: DbMatchKind.optional(),
    dbUser: z.array(z.string()).optional(),
    database: z.string().optional(),
    applicationName: z.string().optional(),
    clientIdentity: z.string().optional(),
    decision: DbConnectionDecision,
    message: z.string().optional(),
    timeout: z.string().optional(),
  })
  .passthrough();

// ─── PolicyDefinition ───────────────────────────────────────

/**
 * Local-property checks for DB rules that catch silent-bug configs.
 * Emits one zod issue per finding so the user sees all problems in a
 * single parse rather than fixing them one round-trip at a time.
 *
 * Intentionally deferred to agentsh's startup validator (it has the full
 * service catalog and IP-range tables; duplicating that in TS would drift
 * the moment agentsh updates):
 *   - tls_mode: terminate_plaintext_upstream upstream loopback/private check
 *   - catalog selector (relations/functions) + service-mode interaction
 *   - "unsafe allow rule" check (decision: allow + operations: ['*'] no filter)
 *   - operation alias expansion correctness
 *   - approval timeout ≤ 600s
 *   - object resolution tag runtime semantics
 */
function validateDbRules(
  policy: {
    databaseRules?: Array<{ name: string; operations?: string[]; decision: string; redirect?: { relation: string }; requireWhere?: boolean }>;
    databaseConnectionRules?: Array<{ name: string; matchKind?: string; decision: string }>;
  },
  ctx: z.RefinementCtx,
): void {
  // 1. operations[] required and non-empty for every database rule
  // 2. decision: redirect requires redirect.relation
  // (combined in one pass over databaseRules for clarity)
  (policy.databaseRules ?? []).forEach((r, i) => {
    if (!r.operations || r.operations.length === 0) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['databaseRules', i, 'operations'],
        message: `databaseRules["${r.name}"]: operations must be a non-empty array`,
      });
    }
    if (r.decision === 'redirect' && !r.redirect?.relation) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['databaseRules', i, 'redirect'],
        message: `databaseRules["${r.name}"]: decision "redirect" requires redirect.relation to be set`,
      });
    }
    // require_where: true is only valid when operations contain only modify/delete groups
    if (r.requireWhere === true) {
      const KNOWN_INCOMPATIBLE = new Set([
        'read', 'write', 'bulk_load', 'bulk_export',
        'schema_create', 'schema_alter', 'schema_destroy',
        'privilege', 'transaction', 'session', 'maintenance',
        'lock', 'notify', 'procedural', 'unsafe_io', 'unknown', '*',
        'READ', 'INSERT', 'CREATE', 'DROP', 'ALTER', 'TRUNCATE',
        'EXPORT', 'LOAD', 'SCHEMA', 'MAINTENANCE',
        'LOCK_TABLES', 'LISTEN_NOTIFY', 'DANGEROUS',
      ]);
      const hasIncompatible = (r.operations ?? []).some(op => KNOWN_INCOMPATIBLE.has(op));
      if (hasIncompatible) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['databaseRules', i, 'requireWhere'],
          message: `databaseRules["${r.name}"]: require_where is supported only for modify/delete operations`,
        });
      }
    }
  });

  // 3. (handled at schema level — DbConnectionDecision enum doesn't include 'redirect')

  // 4. matchKind 'cancel' + decision 'approve' is impossible (cancel is real-time)
  (policy.databaseConnectionRules ?? []).forEach((r, i) => {
    if (r.matchKind === 'cancel' && r.decision === 'approve') {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['databaseConnectionRules', i, 'decision'],
        message: `databaseConnectionRules["${r.name}"]: matchKind "cancel" cannot use decision "approve" — cancel requests are real-time and cannot be held for approval`,
      });
    }
  });

  // 5. Duplicate names within each list
  const seenDbRuleNames = new Set<string>();
  (policy.databaseRules ?? []).forEach((r, i) => {
    if (seenDbRuleNames.has(r.name)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['databaseRules', i, 'name'],
        message: `databaseRules["${r.name}"]: duplicate rule name`,
      });
    }
    seenDbRuleNames.add(r.name);
  });
  const seenConnRuleNames = new Set<string>();
  (policy.databaseConnectionRules ?? []).forEach((r, i) => {
    if (seenConnRuleNames.has(r.name)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['databaseConnectionRules', i, 'name'],
        message: `databaseConnectionRules["${r.name}"]: duplicate rule name`,
      });
    }
    seenConnRuleNames.add(r.name);
  });
}

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
    httpServices: z.array(HttpServiceSchema).optional(),
    // DB access (v0.20+)
    dbServices: z.record(z.string(), DbServiceDefSchema).optional(),
    databaseRules: z.array(DatabaseRuleSchema).optional(),
    databaseConnectionRules: z.array(DatabaseConnectionRuleSchema).optional(),
  })
  .strict()
  .superRefine((policy, ctx) => {
    validateDbRules(policy, ctx);
  });

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
export type HttpServiceSecret = z.infer<typeof HttpServiceSecretSchema>;
export type HttpServiceInjectHeader = z.infer<typeof HttpServiceInjectHeaderSchema>;
export type HttpServiceInject = z.infer<typeof HttpServiceInjectSchema>;
export type HttpServiceRule = z.infer<typeof HttpServiceRuleSchema>;
export type HttpService = z.infer<typeof HttpServiceSchema>;
export type DbServiceDef = z.infer<typeof DbServiceDefSchema>;
export type DatabaseRule = z.infer<typeof DatabaseRuleSchema>;
export type DatabaseConnectionRule = z.infer<typeof DatabaseConnectionRuleSchema>;

/**
 * Canonical DB operation groups (per agentsh spec §5). These are the underlying
 * group names that aliases expand to at policy-load time inside agentsh.
 *
 * Exported as a hint union for editor autocomplete; the schema accepts any
 * string so new agentsh operations don't break the binding.
 */
export type DbOperationGroup =
  | 'read'
  | 'write'
  | 'modify'
  | 'delete'
  | 'bulk_load'
  | 'bulk_export'
  | 'schema_create'
  | 'schema_alter'
  | 'schema_destroy'
  | 'privilege'
  | 'transaction'
  | 'session'
  | 'maintenance'
  | 'lock'
  | 'notify'
  | 'procedural'
  | 'unsafe_io'
  | 'unknown';

/**
 * Common DB operation aliases (per agentsh spec §5). Aliases expand to one or
 * more groups at policy-load time inside agentsh. Hint-only — schema accepts
 * any string.
 */
export type DbOperationAlias =
  | 'READ'
  | 'INSERT'
  | 'UPDATE'
  | 'DELETE'
  | 'REMOVE'
  | 'CREATE'
  | 'DROP'
  | 'ALTER'
  | 'TRUNCATE'
  | 'EXPORT'
  | 'LOAD'
  | 'MUTATE'
  | 'SCHEMA'
  | 'MAINTENANCE'
  | 'LOCK_TABLES'
  | 'LISTEN_NOTIFY'
  | 'DANGEROUS'
  | '*';

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
