# Database access bindings for `@agentsh/secure-sandbox`

## Context

Agentsh v0.20.0 introduced a new database-access subsystem with three new policy concepts (`db_services`, `database_rules`, `database_connection_rules`) and a server-config block (`policies.db`) for runtime defaults like statement logging and approval previews. The full schema lives in `/home/eran/work/agentsh/internal/db/policy/` and is referenced from `docs/db-access-spec*.md` upstream.

`@agentsh/secure-sandbox` is the TypeScript wrapper around agentsh's config + policy YAML. After the v0.20.0 bump we have zero bindings for any of this — users who want database policy must hand-edit YAML. This spec adds first-class bindings.

This is sub-project **A** of a six-part full-parity audit. The other five sub-projects (audit pipeline, auth, sandbox additions, top-level platform/policies, drift audit) are out of scope and will get their own specs.

## Design decisions

Settled during brainstorming:

| Decision | Choice | Reasoning |
|---|---|---|
| API shape | Mirror agentsh layout — three new top-level keys in `PolicyDefinition`, one new optional block in `ServerConfigOpts` | Every existing `PolicyDefinition` key 1-to-1 mirrors agentsh; introducing a wrapping `db` namespace would be the first place we diverge. Matches `unixSocketRules` / `signalRules` precedent for `Rules` suffix on ambiguous nouns. |
| Adapter defaults | None ship DB defaults | "Whatever agentsh has" — agentsh's `applyDefaults*` already populates `log_statements: parameters_redacted`, `approval_statement_preview_chars: 200`, etc. Matches how `httpServices` / `signalRules` are handled. |
| Validation depth | Structural + 5 high-value semantic checks for silent-bug configs; defer everything cross-rule / runtime-dependent to agentsh | Modeled exactly on `validateSeccompDetails` in `src/core/config.ts:216-242`. Catches local-property bugs without duplicating agentsh's evolving validator. |
| Operation/group/alias typing | `z.enum` for closed-set fields (decisions, tls_mode, match_kind, deny_mode_in_tx, dbPolicy enums); `z.string()` for open vocab (operations, subtypes); exported TS hint unions for `DbOperationGroup` / `DbOperationAlias` for editor autocomplete only | Mirrors existing split — `FileOpSchema = z.string()` (open) vs decision enums (closed). New operations in agentsh don't break our schema. |

## Files touched

```
src/policies/schema.ts          (+ ~150 lines)
src/policies/serialize.ts       (+ ~90 lines)
src/policies/serialize.test.ts  (+ ~150 lines)
src/policies/schema.test.ts     (+ ~100 lines)
src/core/config.ts              (+ ~50 lines)
src/core/config.test.ts         (+ ~60 lines)
docs/api.md                     (+ ~150 lines)
docs/SPEC-v2.md                 (+ ~100 lines)
```

No new dependencies. No adapter changes. No e2e changes.

## Schema additions (`src/policies/schema.ts`)

Add the following before `PolicyDefinition`:

```ts
// ── DB services ───────────────────────────────────────────────
const DbTlsMode = z.enum([
  'passthrough', 'terminate_reissue', 'terminate_plaintext_upstream',
]);

export const DbServiceDefSchema = z.object({
  family: z.string(),                    // e.g. 'postgres' | 'mysql' | 'mongo'
  dialect: z.string(),                   // e.g. 'postgres' | 'aurora_postgres' | 'redshift'
  upstream: z.string(),                  // host:port
  tlsMode: DbTlsMode,
  allowFunctionCallProtocol: z.boolean().optional(),
  allowGssEncryption: z.boolean().optional(),
  trustedNetwork: z.boolean().optional(),
}).passthrough();

// ── Statement rules ───────────────────────────────────────────
const DbDecision = z.enum(['allow','deny','approve','audit','redirect']);
const DbObjectResolution = z.enum([
  'qualified_syntactic','unqualified_syntactic',
  'ambiguous_after_search_path','maybe_temp_shadowed',
  'unresolved','catalog_resolved','*',
]);
const DbDenyModeInTx = z.enum(['terminate','rollback_then_continue']);

export const DatabaseRuleSchema = z.object({
  name: z.string(),
  dbService: z.string().optional(),
  dbFamily: z.string().optional(),
  dbDialect: z.string().optional(),
  schemas: z.array(z.string()).optional(),
  objects: z.array(z.string()).optional(),
  relations: z.array(z.string()).optional(),
  functions: z.array(z.string()).optional(),
  operations: z.array(z.string()),       // open vocab
  subtypes: z.array(z.string()).optional(),
  matchObjectResolution: DbObjectResolution.optional(),
  decision: DbDecision,
  message: z.string().optional(),
  timeout: z.string().optional(),        // e.g. '60s'
  redirect: z.object({ relation: z.string() }).optional(),
  acknowledgeAuditOnDangerous: z.boolean().optional(),
  denyModeInTx: DbDenyModeInTx.optional(),
}).passthrough();

// ── Connection rules ──────────────────────────────────────────
const DbConnectionDecision = z.enum(['allow','deny','approve','audit']);
const DbMatchKind = z.enum(['connect','cancel','replication']);

export const DatabaseConnectionRuleSchema = z.object({
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
}).passthrough();
```

Add to `PolicyDefinitionSchema`:

```ts
dbServices: z.record(z.string(), DbServiceDefSchema).optional(),
databaseRules: z.array(DatabaseRuleSchema).optional(),
databaseConnectionRules: z.array(DatabaseConnectionRuleSchema).optional(),
```

Exported types and hint unions:

```ts
export type DbServiceDef = z.infer<typeof DbServiceDefSchema>;
export type DatabaseRule = z.infer<typeof DatabaseRuleSchema>;
export type DatabaseConnectionRule = z.infer<typeof DatabaseConnectionRuleSchema>;

export type DbOperationGroup =
  | 'read' | 'write' | 'modify' | 'delete' | 'bulk_load' | 'bulk_export'
  | 'schema_create' | 'schema_alter' | 'schema_destroy' | 'privilege'
  | 'transaction' | 'session' | 'maintenance' | 'lock' | 'notify'
  | 'procedural' | 'unsafe_io' | 'unknown';

export type DbOperationAlias =
  | 'READ' | 'INSERT' | 'UPDATE' | 'DELETE' | 'REMOVE' | 'CREATE' | 'DROP'
  | 'ALTER' | 'TRUNCATE' | 'EXPORT' | 'LOAD' | 'MUTATE' | 'SCHEMA'
  | 'MAINTENANCE' | 'LOCK_TABLES' | 'LISTEN_NOTIFY' | 'DANGEROUS' | '*';
```

## Validation (`src/policies/schema.ts`)

Add `validateDbRules()` returning an error string or `null`, wired into `PolicyDefinitionSchema.refine()`:

```ts
function validateDbRules(policy: PolicyDefinition): string | null {
  // 1. operations[] required and non-empty for every database rule
  for (const r of policy.databaseRules ?? []) {
    if (!r.operations || r.operations.length === 0) {
      return `databaseRules["${r.name}"]: operations must be a non-empty array`;
    }
  }
  // 2. decision: redirect requires a redirect.relation
  for (const r of policy.databaseRules ?? []) {
    if (r.decision === 'redirect' && !r.redirect?.relation) {
      return `databaseRules["${r.name}"]: decision "redirect" requires redirect.relation to be set`;
    }
  }
  // 3. (handled at schema level — DbConnectionDecision enum doesn't include 'redirect')
  // 4. matchKind 'cancel' + decision 'approve' is impossible
  for (const r of policy.databaseConnectionRules ?? []) {
    if (r.matchKind === 'cancel' && r.decision === 'approve') {
      return `databaseConnectionRules["${r.name}"]: matchKind "cancel" cannot use decision "approve" — cancel requests are real-time and cannot be held for approval`;
    }
  }
  // 5. Duplicate names within each list (mirrors validateSeccompDetails)
  const seenSvc = new Set<string>();
  for (const r of policy.databaseRules ?? []) {
    if (seenSvc.has(r.name)) return `databaseRules["${r.name}"]: duplicate rule name`;
    seenSvc.add(r.name);
  }
  const seenConn = new Set<string>();
  for (const r of policy.databaseConnectionRules ?? []) {
    if (seenConn.has(r.name)) return `databaseConnectionRules["${r.name}"]: duplicate rule name`;
    seenConn.add(r.name);
  }
  return null;
}
```

**Not validated** (defer to agentsh's startup validator):

- `tls_mode: terminate_plaintext_upstream` upstream-host loopback/private check
- Catalog selector + non-Postgres / non-terminate service interaction
- Unsafe allow rule (`decision: allow` + `operations: ['*']` no filter)
- Operation alias expansion correctness
- Object resolution tag semantics
- Approval timeout > 600s

A `ProvisioningError` thrown at `secureSandbox()` is an acceptable failure mode for these.

Wire into `PolicyDefinitionSchema` via `superRefine` so the validator runs exactly once per parse:

```ts
export const PolicyDefinitionSchema = z.object({ ... }).superRefine((policy, ctx) => {
  const err = validateDbRules(policy);
  if (err) ctx.addIssue({ code: z.ZodIssueCode.custom, message: err });
});
```

## Serialization (`src/policies/serialize.ts`)

Three new helpers, three new emit blocks in `serializePolicy`. All follow existing patterns (omit when empty, snake_case keys, mechanical).

### `serializeDbService`

```ts
function serializeDbService(def: DbServiceDef): Record<string, unknown> {
  const out: Record<string, unknown> = {
    family: def.family,
    dialect: def.dialect,
    upstream: def.upstream,
    tls_mode: def.tlsMode,
  };
  if (def.allowFunctionCallProtocol !== undefined) out.allow_function_call_protocol = def.allowFunctionCallProtocol;
  if (def.allowGssEncryption !== undefined) out.allow_gss_encryption = def.allowGssEncryption;
  if (def.trustedNetwork !== undefined) out.trusted_network = def.trustedNetwork;
  return out;
}
```

### `serializeDatabaseRule`

```ts
function serializeDatabaseRule(rule: DatabaseRule): Record<string, unknown> {
  const out: Record<string, unknown> = {
    name: rule.name,
    operations: rule.operations,
    decision: rule.decision,
  };
  if (rule.dbService) out.db_service = rule.dbService;
  if (rule.dbFamily) out.db_family = rule.dbFamily;
  if (rule.dbDialect) out.db_dialect = rule.dbDialect;
  if (rule.schemas?.length) out.schemas = rule.schemas;
  if (rule.objects?.length) out.objects = rule.objects;
  if (rule.relations?.length) out.relations = rule.relations;
  if (rule.functions?.length) out.functions = rule.functions;
  if (rule.subtypes?.length) out.subtypes = rule.subtypes;
  if (rule.matchObjectResolution) out.match_object_resolution = rule.matchObjectResolution;
  if (rule.message) out.message = rule.message;
  if (rule.timeout) out.timeout = rule.timeout;
  if (rule.redirect) out.redirect = { relation: rule.redirect.relation };
  if (rule.acknowledgeAuditOnDangerous !== undefined) out.acknowledge_audit_on_dangerous = rule.acknowledgeAuditOnDangerous;
  if (rule.denyModeInTx) out.deny_mode_in_tx = rule.denyModeInTx;
  return out;
}
```

### `serializeDatabaseConnectionRule`

```ts
function serializeDatabaseConnectionRule(rule: DatabaseConnectionRule): Record<string, unknown> {
  const out: Record<string, unknown> = {
    name: rule.name,
    decision: rule.decision,
  };
  if (rule.dbService) out.db_service = rule.dbService;
  if (rule.matchKind) out.match_kind = rule.matchKind;
  if (rule.dbUser?.length) out.db_user = rule.dbUser;
  if (rule.database) out.database = rule.database;
  if (rule.applicationName) out.application_name = rule.applicationName;
  if (rule.clientIdentity) out.client_identity = rule.clientIdentity;
  if (rule.message) out.message = rule.message;
  if (rule.timeout) out.timeout = rule.timeout;
  return out;
}
```

### Emit blocks in `serializePolicy`

Append after existing rule sections, before `audit`:

```ts
if (policy.dbServices && Object.keys(policy.dbServices).length > 0) {
  out.db_services = Object.fromEntries(
    Object.entries(policy.dbServices).map(([k, v]) => [k, serializeDbService(v)])
  );
}
if (policy.databaseRules?.length) {
  out.database_rules = policy.databaseRules.map(serializeDatabaseRule);
}
if (policy.databaseConnectionRules?.length) {
  out.database_connection_rules = policy.databaseConnectionRules.map(serializeDatabaseConnectionRule);
}
```

## `dbPolicy` in `ServerConfigOpts` (`src/core/config.ts`)

Add to the `ServerConfigOpts` interface:

```ts
dbPolicy?: {
  logStatements?: 'none' | 'parameters_redacted' | 'full';
  approvalStatementPreview?: 'redacted' | 'full';
  approvalStatementPreviewChars?: number;
  unavoidability?: 'off' | 'required';
  escalateUnknownFunctions?: boolean;
  safeFunctionAllowlist?: string[];
};
```

In `generateServerConfig`, only emit when set so agentsh's defaults take effect otherwise:

```ts
if (opts.dbPolicy) {
  const db: Record<string, unknown> = {};
  if (opts.dbPolicy.logStatements) db.log_statements = opts.dbPolicy.logStatements;
  if (opts.dbPolicy.approvalStatementPreview) db.approval_statement_preview = opts.dbPolicy.approvalStatementPreview;
  if (opts.dbPolicy.approvalStatementPreviewChars !== undefined) db.approval_statement_preview_chars = opts.dbPolicy.approvalStatementPreviewChars;
  if (opts.dbPolicy.unavoidability) db.unavoidability = opts.dbPolicy.unavoidability;
  if (opts.dbPolicy.escalateUnknownFunctions !== undefined) db.escalate_unknown_functions = opts.dbPolicy.escalateUnknownFunctions;
  if (opts.dbPolicy.safeFunctionAllowlist?.length) db.safe_function_allowlist = opts.dbPolicy.safeFunctionAllowlist;
  if (Object.keys(db).length) (config.policies as any).db = db;
}
```

## Tests

### `src/policies/schema.test.ts` (+ ~100 lines)

- Accepts minimal valid `dbServices` (single Postgres `terminate_reissue` service)
- Accepts database rule with `operations: ['*']` + `decision: 'deny'`
- Accepts connection rule with `matchKind: 'cancel'` + `decision: 'deny'`
- Rejects `operations: []` — error message mentions "non-empty"
- Rejects `decision: 'redirect'` without `redirect.relation`
- Rejects connection rule with `decision: 'redirect'` (enum doesn't include it)
- Rejects connection rule with `matchKind: 'cancel'` + `decision: 'approve'` — message mentions "real-time"
- Rejects duplicate `name` in `databaseRules`
- Rejects duplicate `name` in `databaseConnectionRules`
- Accepts open-vocab `operations: ['my_future_op']`
- Accepts open-vocab `subtypes: ['my_subtype']`
- `.passthrough()` preserves unknown fields on `DatabaseRule`

### `src/policies/serialize.test.ts` (+ ~150 lines)

- Empty `dbServices` / `databaseRules` / `databaseConnectionRules` → keys absent from YAML
- One service per `tlsMode` value → correct `tls_mode`, optional flags omitted when not set
- Database rule with every optional field → all camelCase → snake_case mappings correct
- Connection rule with `dbUser: ['app', 'reader']` → `db_user: [...]`
- Redirect rule → `redirect: { relation: 'public.canonical' }`
- `denyModeInTx: 'rollback_then_continue'` → `deny_mode_in_tx: rollback_then_continue`
- `matchObjectResolution: 'catalog_resolved'` → `match_object_resolution: catalog_resolved`
- `acknowledgeAuditOnDangerous: true` → `acknowledge_audit_on_dangerous: true`
- Output ordering deterministic (so YAML diffs stay stable across runs)

### `src/core/config.test.ts` (+ ~60 lines)

- `dbPolicy` unset → no `policies.db` key in output
- `dbPolicy: { logStatements: 'full' }` → `policies.db: { log_statements: full }` (no other fields)
- Full `dbPolicy` set → all six fields under `policies.db` in snake_case
- `safeFunctionAllowlist: []` → key omitted (matches existing pattern)

## Docs

- `docs/api.md` (+ ~150 lines): new **Database access** section with subsections for Services, Statement rules, Connection rules, `dbPolicy`. Worked example for each. Cross-link to agentsh upstream spec for the operation taxonomy / subtype list (so we don't duplicate the canonical reference).
- `docs/SPEC-v2.md` (+ ~100 lines): schema reference rows under a new `## Database` heading.

## Verification

- `npm test` — should grow from 646 to ~700+ tests; all pass
- `npm run typecheck` — clean
- `npm run build` — clean

No e2e changes — none of our existing e2e platforms have a database under test. End-to-end DB validation will land when a downstream user wires a real database in.

## Out of scope

Explicitly NOT in this spec:

- Adapter `*Defaults()` changes — none ship DB defaults
- New e2e tests for DB
- Side-by-side drift audit of non-DB fields (sub-project **F**)
- Audit pipeline / auth / sandbox / top-level additions (sub-projects **B**/**C**/**D**/**E**)
- Operation alias expansion or runtime semantics in TypeScript — defer to agentsh
