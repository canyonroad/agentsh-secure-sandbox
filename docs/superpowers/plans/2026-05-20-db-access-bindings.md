# DB Access Bindings Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add TypeScript bindings for agentsh v0.20.0's database-access subsystem — `db_services`, `database_rules`, `database_connection_rules` in `PolicyDefinition`, plus `dbPolicy` in `ServerConfigOpts` — so users can configure DB policy with type-safe, validated TS rather than hand-edited YAML.

**Architecture:** Pure additive TypeScript — three new zod schemas in `src/policies/schema.ts`, one `superRefine`-based validator, three new serializers in `src/policies/serialize.ts` wired into `serializePolicy`, one new optional field on `ServerConfigOpts` in `src/core/config.ts` with a single emit branch in `generateServerConfig`. No new dependencies. No runtime changes. No adapter `*Defaults()` changes — agentsh's own `applyDefaults*` populates DB defaults server-side.

**Tech Stack:** TypeScript 5.x, zod, vitest, js-yaml (existing project dependencies).

**Spec:** `docs/superpowers/specs/2026-05-20-db-access-bindings-design.md`

---

## Task 1: Pre-flight check and feature branch

**Files:**
- (none modified)

- [ ] **Step 1: Confirm baseline tests are green**

Run: `npm test`
Expected: 646 tests pass, 16 test files

- [ ] **Step 2: Confirm baseline typecheck is clean**

Run: `npm run typecheck`
Expected: no output (exit 0)

- [ ] **Step 3: Create or switch to a feature branch**

If the current branch already isolates this work (e.g., `db-access-bindings`), stay on it. Otherwise:

```bash
git checkout -b db-access-bindings
```

If the in-flight v0.20.0 bump changes are uncommitted on `main`, they may stay in the working tree — they don't conflict with this work and the DB bindings are pure schema/serializer additions that don't depend on runtime agentsh behavior.

- [ ] **Step 4: Confirm the spec exists**

Run: `cat docs/superpowers/specs/2026-05-20-db-access-bindings-design.md | head -20`
Expected: file present, header reads `# Database access bindings for @agentsh/secure-sandbox`

---

## Task 2: Add `DbServiceDefSchema` with tests

**Files:**
- Modify: `src/policies/schema.ts` (add new schema block before `PolicyDefinitionSchema` at line 308)
- Modify: `src/policies/schema.test.ts` (add new `describe` block)

- [ ] **Step 1: Write the failing tests first**

Append to `src/policies/schema.test.ts`:

```ts
describe('DbServiceDefSchema', () => {
  it('accepts a minimal Postgres terminate_reissue service', () => {
    const result = DbServiceDefSchema.safeParse({
      family: 'postgres',
      dialect: 'postgres',
      upstream: '127.0.0.1:5432',
      tlsMode: 'terminate_reissue',
    });
    expect(result.success).toBe(true);
  });

  it('accepts all optional flags', () => {
    const result = DbServiceDefSchema.safeParse({
      family: 'postgres',
      dialect: 'aurora_postgres',
      upstream: 'db.local:5432',
      tlsMode: 'terminate_plaintext_upstream',
      allowFunctionCallProtocol: true,
      allowGssEncryption: false,
      trustedNetwork: true,
    });
    expect(result.success).toBe(true);
  });

  it('rejects an unknown tlsMode', () => {
    const result = DbServiceDefSchema.safeParse({
      family: 'postgres',
      dialect: 'postgres',
      upstream: '127.0.0.1:5432',
      tlsMode: 'bogus',
    });
    expect(result.success).toBe(false);
  });

  it('requires family, dialect, upstream, tlsMode', () => {
    const result = DbServiceDefSchema.safeParse({ family: 'postgres' });
    expect(result.success).toBe(false);
  });

  it('preserves unknown forward-compat fields via passthrough', () => {
    const result = DbServiceDefSchema.safeParse({
      family: 'postgres',
      dialect: 'postgres',
      upstream: '127.0.0.1:5432',
      tlsMode: 'passthrough',
      newFutureField: 'whatever',
    });
    expect(result.success).toBe(true);
    if (result.success) {
      expect((result.data as any).newFutureField).toBe('whatever');
    }
  });
});
```

Also add `DbServiceDefSchema` to the imports at the top of `schema.test.ts` (alongside the existing schema imports).

- [ ] **Step 2: Run the tests; expect failures**

Run: `npx vitest run src/policies/schema.test.ts -t "DbServiceDefSchema"`
Expected: 5 failing tests (`DbServiceDefSchema is not exported` / undefined)

- [ ] **Step 3: Add the schema to `src/policies/schema.ts`**

Insert immediately before the `// ─── PolicyDefinition ───` comment block (currently at line 308):

```ts
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
```

- [ ] **Step 4: Run the tests; expect passes**

Run: `npx vitest run src/policies/schema.test.ts -t "DbServiceDefSchema"`
Expected: 5 passing tests

- [ ] **Step 5: Commit**

```bash
git add src/policies/schema.ts src/policies/schema.test.ts
git commit -m "$(cat <<'EOF'
feat(schema): add DbServiceDefSchema for DB access bindings

First piece of sub-project A (DB access bindings) per the spec at
docs/superpowers/specs/2026-05-20-db-access-bindings-design.md.

Adds the DbServiceDefSchema zod schema with the three required fields
(family, dialect, upstream, tlsMode), three optional flags, .passthrough()
for forward-compat, and tests covering shape + tlsMode enum + required
fields + passthrough preservation.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: Add `DatabaseRuleSchema` with tests

**Files:**
- Modify: `src/policies/schema.ts`
- Modify: `src/policies/schema.test.ts`

- [ ] **Step 1: Write the failing tests**

Append to `src/policies/schema.test.ts`:

```ts
describe('DatabaseRuleSchema', () => {
  const minimal = {
    name: 'allow-reads',
    operations: ['read'],
    decision: 'allow' as const,
  };

  it('accepts a minimal rule', () => {
    const result = DatabaseRuleSchema.safeParse(minimal);
    expect(result.success).toBe(true);
  });

  it('accepts every documented enum value for decision', () => {
    for (const decision of ['allow', 'deny', 'approve', 'audit', 'redirect'] as const) {
      const result = DatabaseRuleSchema.safeParse({
        name: `r-${decision}`,
        operations: ['read'],
        decision,
        ...(decision === 'redirect' ? { redirect: { relation: 'public.canonical' } } : {}),
      });
      expect(result.success).toBe(true);
    }
  });

  it('rejects unknown decision values', () => {
    const result = DatabaseRuleSchema.safeParse({
      ...minimal,
      decision: 'maybe',
    });
    expect(result.success).toBe(false);
  });

  it('accepts every documented matchObjectResolution value', () => {
    for (const tag of [
      'qualified_syntactic',
      'unqualified_syntactic',
      'ambiguous_after_search_path',
      'maybe_temp_shadowed',
      'unresolved',
      'catalog_resolved',
      '*',
    ] as const) {
      const result = DatabaseRuleSchema.safeParse({
        ...minimal,
        matchObjectResolution: tag,
      });
      expect(result.success).toBe(true);
    }
  });

  it('accepts denyModeInTx enum values', () => {
    for (const m of ['terminate', 'rollback_then_continue'] as const) {
      const result = DatabaseRuleSchema.safeParse({ ...minimal, denyModeInTx: m });
      expect(result.success).toBe(true);
    }
  });

  it('accepts open-vocab operations (not constrained to a fixed enum)', () => {
    const result = DatabaseRuleSchema.safeParse({
      ...minimal,
      operations: ['my_future_operation_name'],
    });
    expect(result.success).toBe(true);
  });

  it('accepts open-vocab subtypes', () => {
    const result = DatabaseRuleSchema.safeParse({
      ...minimal,
      subtypes: ['my_subtype'],
    });
    expect(result.success).toBe(true);
  });

  it('preserves unknown forward-compat fields via passthrough', () => {
    const result = DatabaseRuleSchema.safeParse({
      ...minimal,
      newFutureField: 42,
    });
    expect(result.success).toBe(true);
    if (result.success) {
      expect((result.data as any).newFutureField).toBe(42);
    }
  });
});
```

Add `DatabaseRuleSchema` to the imports.

- [ ] **Step 2: Run the tests; expect failures**

Run: `npx vitest run src/policies/schema.test.ts -t "DatabaseRuleSchema"`
Expected: ~8 failing tests (`DatabaseRuleSchema is not exported`)

- [ ] **Step 3: Add the schema to `src/policies/schema.ts`**

Immediately after `DbServiceDefSchema`:

```ts
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
    decision: DbDecision,
    message: z.string().optional(),
    timeout: z.string().optional(),
    redirect: z.object({ relation: z.string() }).optional(),
    acknowledgeAuditOnDangerous: z.boolean().optional(),
    denyModeInTx: DbDenyModeInTx.optional(),
  })
  .passthrough();
```

- [ ] **Step 4: Run the tests; expect passes**

Run: `npx vitest run src/policies/schema.test.ts -t "DatabaseRuleSchema"`
Expected: 8 passing tests

- [ ] **Step 5: Commit**

```bash
git add src/policies/schema.ts src/policies/schema.test.ts
git commit -m "$(cat <<'EOF'
feat(schema): add DatabaseRuleSchema for DB statement rules

Adds DatabaseRuleSchema covering name, service/family/dialect filters,
schemas/objects/relations/functions glob lists, operations (open vocab),
subtypes (open vocab), matchObjectResolution enum, decision enum
(allow/deny/approve/audit/redirect), message/timeout/redirect.relation,
acknowledgeAuditOnDangerous, denyModeInTx. Plus tests asserting every
enum value, open vocab acceptance, and passthrough preservation.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: Add `DatabaseConnectionRuleSchema` with tests

**Files:**
- Modify: `src/policies/schema.ts`
- Modify: `src/policies/schema.test.ts`

- [ ] **Step 1: Write the failing tests**

Append to `src/policies/schema.test.ts`:

```ts
describe('DatabaseConnectionRuleSchema', () => {
  const minimal = {
    name: 'allow-connects',
    decision: 'allow' as const,
  };

  it('accepts a minimal rule', () => {
    const result = DatabaseConnectionRuleSchema.safeParse(minimal);
    expect(result.success).toBe(true);
  });

  it('accepts all matchKind values', () => {
    for (const k of ['connect', 'cancel', 'replication'] as const) {
      const result = DatabaseConnectionRuleSchema.safeParse({ ...minimal, matchKind: k });
      expect(result.success).toBe(true);
    }
  });

  it('accepts decision enum without redirect', () => {
    for (const d of ['allow', 'deny', 'approve', 'audit'] as const) {
      const result = DatabaseConnectionRuleSchema.safeParse({ ...minimal, decision: d });
      expect(result.success).toBe(true);
    }
  });

  it('rejects decision: redirect (not supported on connection rules)', () => {
    const result = DatabaseConnectionRuleSchema.safeParse({
      ...minimal,
      decision: 'redirect',
    });
    expect(result.success).toBe(false);
  });

  it('accepts all visibility-restricted optional fields', () => {
    const result = DatabaseConnectionRuleSchema.safeParse({
      ...minimal,
      dbService: 'pg-main',
      dbUser: ['app', 'reader'],
      database: 'production',
      applicationName: 'web-*',
      clientIdentity: 'spiffe://cluster/agent',
      message: 'denied',
      timeout: '60s',
    });
    expect(result.success).toBe(true);
  });

  it('preserves unknown forward-compat fields via passthrough', () => {
    const result = DatabaseConnectionRuleSchema.safeParse({
      ...minimal,
      newFutureField: 'whatever',
    });
    expect(result.success).toBe(true);
    if (result.success) {
      expect((result.data as any).newFutureField).toBe('whatever');
    }
  });
});
```

Add `DatabaseConnectionRuleSchema` to the imports.

- [ ] **Step 2: Run the tests; expect failures**

Run: `npx vitest run src/policies/schema.test.ts -t "DatabaseConnectionRuleSchema"`
Expected: ~6 failing tests

- [ ] **Step 3: Add the schema to `src/policies/schema.ts`**

Immediately after `DatabaseRuleSchema`:

```ts
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
```

- [ ] **Step 4: Run the tests; expect passes**

Run: `npx vitest run src/policies/schema.test.ts -t "DatabaseConnectionRuleSchema"`
Expected: 6 passing tests

- [ ] **Step 5: Commit**

```bash
git add src/policies/schema.ts src/policies/schema.test.ts
git commit -m "$(cat <<'EOF'
feat(schema): add DatabaseConnectionRuleSchema for DB connection rules

Adds DatabaseConnectionRuleSchema with the connection-level decision enum
(allow/deny/approve/audit — no redirect, since connections don't support
it), matchKind enum (connect/cancel/replication), visibility-restricted
fields (dbUser/database/applicationName under non-passthrough TLS, plus
clientIdentity available across all modes), message/timeout, and passthrough
for forward-compat.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 5: Wire DB schemas into `PolicyDefinitionSchema` + export types

**Files:**
- Modify: `src/policies/schema.ts`
- Modify: `src/policies/schema.test.ts`

- [ ] **Step 1: Write the failing tests for PolicyDefinition acceptance**

Append to `src/policies/schema.test.ts`:

```ts
describe('PolicyDefinitionSchema — DB top-level keys', () => {
  it('accepts dbServices as a record of DbServiceDef', () => {
    const result = PolicyDefinitionSchema.safeParse({
      dbServices: {
        'pg-main': {
          family: 'postgres',
          dialect: 'postgres',
          upstream: '127.0.0.1:5432',
          tlsMode: 'terminate_reissue',
        },
      },
    });
    expect(result.success).toBe(true);
  });

  it('accepts databaseRules array', () => {
    const result = PolicyDefinitionSchema.safeParse({
      databaseRules: [
        { name: 'r1', operations: ['read'], decision: 'allow' },
      ],
    });
    expect(result.success).toBe(true);
  });

  it('accepts databaseConnectionRules array', () => {
    const result = PolicyDefinitionSchema.safeParse({
      databaseConnectionRules: [
        { name: 'c1', decision: 'allow' },
      ],
    });
    expect(result.success).toBe(true);
  });

  it('accepts a policy with all three DB sections plus existing sections', () => {
    const result = PolicyDefinitionSchema.safeParse({
      file: [{ allow: '/workspace/**' }],
      dbServices: { 'pg': { family: 'postgres', dialect: 'postgres', upstream: 'h:5432', tlsMode: 'terminate_reissue' } },
      databaseRules: [{ name: 'r', operations: ['read'], decision: 'allow' }],
      databaseConnectionRules: [{ name: 'c', decision: 'allow' }],
    });
    expect(result.success).toBe(true);
  });
});
```

- [ ] **Step 2: Run the tests; expect failures**

Run: `npx vitest run src/policies/schema.test.ts -t "PolicyDefinitionSchema — DB top-level keys"`
Expected: 4 failing tests (`Unrecognized key(s) in object: 'dbServices'` etc., because the existing schema uses `.strict()`)

- [ ] **Step 3: Add the three optional fields to `PolicyDefinitionSchema`**

In `src/policies/schema.ts`, modify the `PolicyDefinitionSchema` object literal (currently at line 310-327) to add three new fields. The full updated block:

```ts
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
  .strict();
```

- [ ] **Step 4: Run the new tests; expect passes**

Run: `npx vitest run src/policies/schema.test.ts -t "PolicyDefinitionSchema — DB top-level keys"`
Expected: 4 passing tests

- [ ] **Step 5: Add inferred types + hint unions at the bottom of `schema.ts`**

After the existing `export type ...` block (currently ending around line 344 with `export type AuditSettings = ...`), append:

```ts
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
```

- [ ] **Step 6: Run typecheck**

Run: `npm run typecheck`
Expected: clean (exit 0)

- [ ] **Step 7: Run the full schema test file**

Run: `npx vitest run src/policies/schema.test.ts`
Expected: all tests pass (existing + new)

- [ ] **Step 8: Commit**

```bash
git add src/policies/schema.ts src/policies/schema.test.ts
git commit -m "$(cat <<'EOF'
feat(schema): wire DB schemas into PolicyDefinition + export types

Adds dbServices/databaseRules/databaseConnectionRules to
PolicyDefinitionSchema, with tests asserting each is accepted as a
top-level optional key alongside the existing rule sections. Exports
inferred TS types for the three rule shapes and two hint unions
(DbOperationGroup, DbOperationAlias) for editor autocomplete.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 6: Add `validateDbRules` + wire `superRefine` + tests

**Files:**
- Modify: `src/policies/schema.ts`
- Modify: `src/policies/schema.test.ts`

- [ ] **Step 1: Write the failing validation tests**

Append to `src/policies/schema.test.ts`:

```ts
describe('PolicyDefinitionSchema — DB validation rules', () => {
  it('rejects database rule with empty operations array', () => {
    const result = PolicyDefinitionSchema.safeParse({
      databaseRules: [
        { name: 'r1', operations: [], decision: 'deny' },
      ],
    });
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error.issues.some(i => i.message.includes('non-empty'))).toBe(true);
    }
  });

  it('rejects decision: redirect without redirect.relation', () => {
    const result = PolicyDefinitionSchema.safeParse({
      databaseRules: [
        { name: 'r1', operations: ['read'], decision: 'redirect' },
      ],
    });
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error.issues.some(i =>
        i.message.includes('redirect.relation')
      )).toBe(true);
    }
  });

  it('accepts decision: redirect when redirect.relation is set', () => {
    const result = PolicyDefinitionSchema.safeParse({
      databaseRules: [
        {
          name: 'r1',
          operations: ['read'],
          decision: 'redirect',
          redirect: { relation: 'public.canonical' },
        },
      ],
    });
    expect(result.success).toBe(true);
  });

  it('rejects connection rule with matchKind: cancel + decision: approve', () => {
    const result = PolicyDefinitionSchema.safeParse({
      databaseConnectionRules: [
        { name: 'c1', matchKind: 'cancel', decision: 'approve' },
      ],
    });
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error.issues.some(i =>
        i.message.includes('real-time')
      )).toBe(true);
    }
  });

  it('rejects duplicate names within databaseRules', () => {
    const result = PolicyDefinitionSchema.safeParse({
      databaseRules: [
        { name: 'r1', operations: ['read'], decision: 'allow' },
        { name: 'r1', operations: ['write'], decision: 'deny' },
      ],
    });
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error.issues.some(i =>
        i.message.includes('duplicate')
      )).toBe(true);
    }
  });

  it('rejects duplicate names within databaseConnectionRules', () => {
    const result = PolicyDefinitionSchema.safeParse({
      databaseConnectionRules: [
        { name: 'c1', decision: 'allow' },
        { name: 'c1', decision: 'deny' },
      ],
    });
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error.issues.some(i =>
        i.message.includes('duplicate')
      )).toBe(true);
    }
  });

  it('allows the same name across the two rule lists (no cross-list duplicate check)', () => {
    const result = PolicyDefinitionSchema.safeParse({
      databaseRules: [{ name: 'shared', operations: ['read'], decision: 'allow' }],
      databaseConnectionRules: [{ name: 'shared', decision: 'allow' }],
    });
    expect(result.success).toBe(true);
  });
});
```

- [ ] **Step 2: Run the tests; expect failures**

Run: `npx vitest run src/policies/schema.test.ts -t "PolicyDefinitionSchema — DB validation rules"`
Expected: 5 failing tests (the cases that should reject currently parse successfully; the 2 acceptance cases pass)

- [ ] **Step 3: Add `validateDbRules` helper + wire `superRefine`**

In `src/policies/schema.ts`, add the validator function immediately before `export const PolicyDefinitionSchema = z` (~line 308):

```ts
/**
 * Local-property checks for DB rules that catch silent-bug configs.
 * Returns null if valid, or the error message string.
 *
 * Cross-rule, runtime-dependent, and TLS-mode interaction checks are
 * intentionally deferred to agentsh's startup validator (it has the full
 * service catalog and IP-range tables; duplicating that in TS would drift
 * the moment agentsh updates).
 */
function validateDbRules(policy: {
  databaseRules?: Array<{ name: string; operations?: string[]; decision: string; redirect?: { relation: string } }>;
  databaseConnectionRules?: Array<{ name: string; matchKind?: string; decision: string }>;
}): string | null {
  // 1. operations[] required and non-empty for every database rule
  for (const r of policy.databaseRules ?? []) {
    if (!r.operations || r.operations.length === 0) {
      return `databaseRules["${r.name}"]: operations must be a non-empty array`;
    }
  }
  // 2. decision: redirect requires redirect.relation
  for (const r of policy.databaseRules ?? []) {
    if (r.decision === 'redirect' && !r.redirect?.relation) {
      return `databaseRules["${r.name}"]: decision "redirect" requires redirect.relation to be set`;
    }
  }
  // 3. (handled at schema level — DbConnectionDecision enum doesn't include 'redirect')
  // 4. matchKind 'cancel' + decision 'approve' is impossible (cancel is real-time)
  for (const r of policy.databaseConnectionRules ?? []) {
    if (r.matchKind === 'cancel' && r.decision === 'approve') {
      return `databaseConnectionRules["${r.name}"]: matchKind "cancel" cannot use decision "approve" — cancel requests are real-time and cannot be held for approval`;
    }
  }
  // 5. Duplicate names within each list (mirrors validateSeccompDetails precedent)
  const seenSvc = new Set<string>();
  for (const r of policy.databaseRules ?? []) {
    if (seenSvc.has(r.name)) {
      return `databaseRules["${r.name}"]: duplicate rule name`;
    }
    seenSvc.add(r.name);
  }
  const seenConn = new Set<string>();
  for (const r of policy.databaseConnectionRules ?? []) {
    if (seenConn.has(r.name)) {
      return `databaseConnectionRules["${r.name}"]: duplicate rule name`;
    }
    seenConn.add(r.name);
  }
  return null;
}
```

Then modify the `PolicyDefinitionSchema` chain to add `.superRefine(...)` after `.strict()`:

```ts
export const PolicyDefinitionSchema = z
  .object({
    // ... (existing fields including the three DB keys added in Task 5)
  })
  .strict()
  .superRefine((policy, ctx) => {
    const err = validateDbRules(policy);
    if (err) ctx.addIssue({ code: z.ZodIssueCode.custom, message: err });
  });
```

- [ ] **Step 4: Run the validation tests; expect passes**

Run: `npx vitest run src/policies/schema.test.ts -t "PolicyDefinitionSchema — DB validation rules"`
Expected: 7 passing tests

- [ ] **Step 5: Run the full schema test file**

Run: `npx vitest run src/policies/schema.test.ts`
Expected: all tests pass (existing + new)

- [ ] **Step 6: Run typecheck**

Run: `npm run typecheck`
Expected: clean

- [ ] **Step 7: Commit**

```bash
git add src/policies/schema.ts src/policies/schema.test.ts
git commit -m "$(cat <<'EOF'
feat(schema): add DB rule validation via superRefine

Five high-value semantic checks modeled on validateSeccompDetails:
non-empty operations, redirect requires redirect.relation, cancel +
approve forbidden, duplicate name within each list. Cross-rule and
runtime-dependent checks (TLS-mode loopback, catalog selector + service
mode, unsafe allow rule, alias expansion, approval timeout cap) are
deferred to agentsh's startup validator with ProvisioningError as the
failure mode.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 7: Add `serializeDbService` with tests

**Files:**
- Modify: `src/policies/serialize.ts`
- Modify: `src/policies/serialize.test.ts`

- [ ] **Step 1: Write the failing tests**

Append to `src/policies/serialize.test.ts` (use the existing `serializePolicy` entry point — it round-trips through YAML, so we test what users actually see):

```ts
describe('serializePolicy — dbServices', () => {
  it('emits db_services with snake_case tls_mode', () => {
    const result = serializePolicy({
      dbServices: {
        'pg-main': {
          family: 'postgres',
          dialect: 'postgres',
          upstream: '127.0.0.1:5432',
          tlsMode: 'terminate_reissue',
        },
      },
    });
    const parsed = yaml.load(result) as any;
    expect(parsed.db_services['pg-main']).toEqual({
      family: 'postgres',
      dialect: 'postgres',
      upstream: '127.0.0.1:5432',
      tls_mode: 'terminate_reissue',
    });
  });

  it('emits all optional flags in snake_case when set', () => {
    const result = serializePolicy({
      dbServices: {
        'aurora': {
          family: 'postgres',
          dialect: 'aurora_postgres',
          upstream: 'aurora.local:5432',
          tlsMode: 'terminate_plaintext_upstream',
          allowFunctionCallProtocol: true,
          allowGssEncryption: false,
          trustedNetwork: true,
        },
      },
    });
    const parsed = yaml.load(result) as any;
    expect(parsed.db_services.aurora.allow_function_call_protocol).toBe(true);
    expect(parsed.db_services.aurora.allow_gss_encryption).toBe(false);
    expect(parsed.db_services.aurora.trusted_network).toBe(true);
  });

  it('omits optional flags when not set', () => {
    const result = serializePolicy({
      dbServices: {
        'minimal': {
          family: 'postgres',
          dialect: 'postgres',
          upstream: 'h:5432',
          tlsMode: 'passthrough',
        },
      },
    });
    const parsed = yaml.load(result) as any;
    expect(parsed.db_services.minimal).not.toHaveProperty('allow_function_call_protocol');
    expect(parsed.db_services.minimal).not.toHaveProperty('allow_gss_encryption');
    expect(parsed.db_services.minimal).not.toHaveProperty('trusted_network');
  });

  it('omits db_services entirely when not set or empty', () => {
    const resultA = serializePolicy({});
    const resultB = serializePolicy({ dbServices: {} });
    expect(yaml.load(resultA) as any).not.toHaveProperty('db_services');
    expect(yaml.load(resultB) as any).not.toHaveProperty('db_services');
  });
});
```

(The `yaml` symbol is already imported in `serialize.test.ts` at line 2 — `import yaml from 'js-yaml'`.)

- [ ] **Step 2: Run the tests; expect failures**

Run: `npx vitest run src/policies/serialize.test.ts -t "serializePolicy — dbServices"`
Expected: 4 failing tests

- [ ] **Step 3: Add the helper to `src/policies/serialize.ts`**

Add `DbServiceDef` to the existing type imports at the top of the file. Then add the helper immediately before `function serializeProviders(...)` (~line 335):

```ts
function serializeDbService(def: DbServiceDef): Record<string, unknown> {
  const out: Record<string, unknown> = {
    family: def.family,
    dialect: def.dialect,
    upstream: def.upstream,
    tls_mode: def.tlsMode,
  };
  if (def.allowFunctionCallProtocol !== undefined) {
    out.allow_function_call_protocol = def.allowFunctionCallProtocol;
  }
  if (def.allowGssEncryption !== undefined) {
    out.allow_gss_encryption = def.allowGssEncryption;
  }
  if (def.trustedNetwork !== undefined) {
    out.trusted_network = def.trustedNetwork;
  }
  return out;
}
```

In `serializePolicy`, immediately after the `unixSocketRules` emit block (currently at lines 453-455) and before `resourceLimits` (line 457), add:

```ts
  if (policy.dbServices && Object.keys(policy.dbServices).length > 0) {
    doc.db_services = Object.fromEntries(
      Object.entries(policy.dbServices).map(([k, v]) => [k, serializeDbService(v)]),
    );
  }
```

- [ ] **Step 4: Run the tests; expect passes**

Run: `npx vitest run src/policies/serialize.test.ts -t "serializePolicy — dbServices"`
Expected: 4 passing tests

- [ ] **Step 5: Commit**

```bash
git add src/policies/serialize.ts src/policies/serialize.test.ts
git commit -m "$(cat <<'EOF'
feat(serialize): emit db_services in policy YAML

Adds serializeDbService helper (tlsMode → tls_mode, optional flags
omitted when unset) and wires it into serializePolicy between
unix_socket_rules and resource_limits. Tests cover snake_case mapping,
all three tlsMode values, optional flag handling, and emit-only-when-set.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 8: Add `serializeDatabaseRule` with tests

**Files:**
- Modify: `src/policies/serialize.ts`
- Modify: `src/policies/serialize.test.ts`

- [ ] **Step 1: Write the failing tests**

Append to `src/policies/serialize.test.ts`:

```ts
describe('serializePolicy — databaseRules', () => {
  it('emits a minimal rule with only required fields', () => {
    const result = serializePolicy({
      databaseRules: [
        { name: 'r1', operations: ['read'], decision: 'allow' },
      ],
    });
    const parsed = yaml.load(result) as any;
    expect(parsed.database_rules).toEqual([
      { name: 'r1', operations: ['read'], decision: 'allow' },
    ]);
  });

  it('emits all snake_case keys when every optional field is set', () => {
    const result = serializePolicy({
      databaseRules: [
        {
          name: 'full',
          dbService: 'pg-main',
          dbFamily: 'postgres',
          dbDialect: 'postgres',
          schemas: ['public'],
          objects: ['users'],
          relations: ['public.users'],
          functions: ['public.f'],
          operations: ['read', 'write'],
          subtypes: ['set_search_path'],
          matchObjectResolution: 'catalog_resolved',
          decision: 'audit',
          message: 'logged',
          timeout: '60s',
          acknowledgeAuditOnDangerous: true,
          denyModeInTx: 'rollback_then_continue',
        },
      ],
    });
    const parsed = yaml.load(result) as any;
    const r = parsed.database_rules[0];
    expect(r.db_service).toBe('pg-main');
    expect(r.db_family).toBe('postgres');
    expect(r.db_dialect).toBe('postgres');
    expect(r.match_object_resolution).toBe('catalog_resolved');
    expect(r.acknowledge_audit_on_dangerous).toBe(true);
    expect(r.deny_mode_in_tx).toBe('rollback_then_continue');
    expect(r.message).toBe('logged');
    expect(r.timeout).toBe('60s');
    expect(r.schemas).toEqual(['public']);
    expect(r.objects).toEqual(['users']);
    expect(r.relations).toEqual(['public.users']);
    expect(r.functions).toEqual(['public.f']);
    expect(r.subtypes).toEqual(['set_search_path']);
  });

  it('emits redirect as a nested object with relation', () => {
    const result = serializePolicy({
      databaseRules: [
        {
          name: 'redir',
          operations: ['read'],
          decision: 'redirect',
          redirect: { relation: 'public.canonical' },
        },
      ],
    });
    const parsed = yaml.load(result) as any;
    expect(parsed.database_rules[0].redirect).toEqual({ relation: 'public.canonical' });
  });

  it('omits database_rules entirely when not set or empty', () => {
    const resultA = serializePolicy({});
    const resultB = serializePolicy({ databaseRules: [] });
    expect(yaml.load(resultA) as any).not.toHaveProperty('database_rules');
    expect(yaml.load(resultB) as any).not.toHaveProperty('database_rules');
  });

  it('omits empty optional arrays', () => {
    const result = serializePolicy({
      databaseRules: [
        {
          name: 'r',
          operations: ['read'],
          decision: 'allow',
          schemas: [],
          objects: [],
          relations: [],
          functions: [],
          subtypes: [],
        },
      ],
    });
    const parsed = yaml.load(result) as any;
    const r = parsed.database_rules[0];
    expect(r).not.toHaveProperty('schemas');
    expect(r).not.toHaveProperty('objects');
    expect(r).not.toHaveProperty('relations');
    expect(r).not.toHaveProperty('functions');
    expect(r).not.toHaveProperty('subtypes');
  });
});
```

- [ ] **Step 2: Run the tests; expect failures**

Run: `npx vitest run src/policies/serialize.test.ts -t "serializePolicy — databaseRules"`
Expected: 5 failing tests

- [ ] **Step 3: Add the helper to `src/policies/serialize.ts`**

Add `DatabaseRule` to the type imports. Add the helper immediately after `serializeDbService`:

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
  if (rule.schemas && rule.schemas.length > 0) out.schemas = rule.schemas;
  if (rule.objects && rule.objects.length > 0) out.objects = rule.objects;
  if (rule.relations && rule.relations.length > 0) out.relations = rule.relations;
  if (rule.functions && rule.functions.length > 0) out.functions = rule.functions;
  if (rule.subtypes && rule.subtypes.length > 0) out.subtypes = rule.subtypes;
  if (rule.matchObjectResolution) out.match_object_resolution = rule.matchObjectResolution;
  if (rule.message) out.message = rule.message;
  if (rule.timeout) out.timeout = rule.timeout;
  if (rule.redirect) out.redirect = { relation: rule.redirect.relation };
  if (rule.acknowledgeAuditOnDangerous !== undefined) {
    out.acknowledge_audit_on_dangerous = rule.acknowledgeAuditOnDangerous;
  }
  if (rule.denyModeInTx) out.deny_mode_in_tx = rule.denyModeInTx;
  return out;
}
```

In `serializePolicy`, immediately after the `dbServices` emit block from Task 7:

```ts
  if (policy.databaseRules && policy.databaseRules.length > 0) {
    doc.database_rules = policy.databaseRules.map(serializeDatabaseRule);
  }
```

- [ ] **Step 4: Run the tests; expect passes**

Run: `npx vitest run src/policies/serialize.test.ts -t "serializePolicy — databaseRules"`
Expected: 5 passing tests

- [ ] **Step 5: Commit**

```bash
git add src/policies/serialize.ts src/policies/serialize.test.ts
git commit -m "$(cat <<'EOF'
feat(serialize): emit database_rules in policy YAML

Adds serializeDatabaseRule helper covering all camelCase → snake_case
mappings (dbService → db_service, matchObjectResolution →
match_object_resolution, acknowledgeAuditOnDangerous →
acknowledge_audit_on_dangerous, denyModeInTx → deny_mode_in_tx) and
omit-when-empty handling for optional array fields. Wires into
serializePolicy after dbServices.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 9: Add `serializeDatabaseConnectionRule` with tests

**Files:**
- Modify: `src/policies/serialize.ts`
- Modify: `src/policies/serialize.test.ts`

- [ ] **Step 1: Write the failing tests**

Append to `src/policies/serialize.test.ts`:

```ts
describe('serializePolicy — databaseConnectionRules', () => {
  it('emits a minimal rule', () => {
    const result = serializePolicy({
      databaseConnectionRules: [
        { name: 'c1', decision: 'allow' },
      ],
    });
    const parsed = yaml.load(result) as any;
    expect(parsed.database_connection_rules).toEqual([
      { name: 'c1', decision: 'allow' },
    ]);
  });

  it('emits all snake_case keys when every optional field is set', () => {
    const result = serializePolicy({
      databaseConnectionRules: [
        {
          name: 'full',
          dbService: 'pg-main',
          matchKind: 'replication',
          dbUser: ['app', 'reader'],
          database: 'production',
          applicationName: 'web-*',
          clientIdentity: 'spiffe://cluster/agent',
          decision: 'approve',
          message: 'reviewing',
          timeout: '120s',
        },
      ],
    });
    const parsed = yaml.load(result) as any;
    const r = parsed.database_connection_rules[0];
    expect(r.db_service).toBe('pg-main');
    expect(r.match_kind).toBe('replication');
    expect(r.db_user).toEqual(['app', 'reader']);
    expect(r.database).toBe('production');
    expect(r.application_name).toBe('web-*');
    expect(r.client_identity).toBe('spiffe://cluster/agent');
    expect(r.message).toBe('reviewing');
    expect(r.timeout).toBe('120s');
  });

  it('omits database_connection_rules entirely when not set or empty', () => {
    const resultA = serializePolicy({});
    const resultB = serializePolicy({ databaseConnectionRules: [] });
    expect(yaml.load(resultA) as any).not.toHaveProperty('database_connection_rules');
    expect(yaml.load(resultB) as any).not.toHaveProperty('database_connection_rules');
  });

  it('omits empty dbUser array', () => {
    const result = serializePolicy({
      databaseConnectionRules: [
        { name: 'c', decision: 'allow', dbUser: [] },
      ],
    });
    const parsed = yaml.load(result) as any;
    expect(parsed.database_connection_rules[0]).not.toHaveProperty('db_user');
  });
});
```

- [ ] **Step 2: Run the tests; expect failures**

Run: `npx vitest run src/policies/serialize.test.ts -t "serializePolicy — databaseConnectionRules"`
Expected: 4 failing tests

- [ ] **Step 3: Add the helper to `src/policies/serialize.ts`**

Add `DatabaseConnectionRule` to the type imports. Add the helper immediately after `serializeDatabaseRule`:

```ts
function serializeDatabaseConnectionRule(rule: DatabaseConnectionRule): Record<string, unknown> {
  const out: Record<string, unknown> = {
    name: rule.name,
    decision: rule.decision,
  };
  if (rule.dbService) out.db_service = rule.dbService;
  if (rule.matchKind) out.match_kind = rule.matchKind;
  if (rule.dbUser && rule.dbUser.length > 0) out.db_user = rule.dbUser;
  if (rule.database) out.database = rule.database;
  if (rule.applicationName) out.application_name = rule.applicationName;
  if (rule.clientIdentity) out.client_identity = rule.clientIdentity;
  if (rule.message) out.message = rule.message;
  if (rule.timeout) out.timeout = rule.timeout;
  return out;
}
```

In `serializePolicy`, immediately after the `databaseRules` emit block:

```ts
  if (policy.databaseConnectionRules && policy.databaseConnectionRules.length > 0) {
    doc.database_connection_rules = policy.databaseConnectionRules.map(
      serializeDatabaseConnectionRule,
    );
  }
```

- [ ] **Step 4: Run the tests; expect passes**

Run: `npx vitest run src/policies/serialize.test.ts -t "serializePolicy — databaseConnectionRules"`
Expected: 4 passing tests

- [ ] **Step 5: Run the full serialize test file**

Run: `npx vitest run src/policies/serialize.test.ts`
Expected: all tests pass (existing + DB additions)

- [ ] **Step 6: Run typecheck**

Run: `npm run typecheck`
Expected: clean

- [ ] **Step 7: Commit**

```bash
git add src/policies/serialize.ts src/policies/serialize.test.ts
git commit -m "$(cat <<'EOF'
feat(serialize): emit database_connection_rules in policy YAML

Adds serializeDatabaseConnectionRule helper (matchKind → match_kind,
dbUser → db_user, applicationName → application_name, clientIdentity →
client_identity) with omit-when-empty for the dbUser array. Wires into
serializePolicy after database_rules.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 10: Add `dbPolicy` to `ServerConfigOpts` with tests

**Files:**
- Modify: `src/core/config.ts`
- Modify: `src/core/config.test.ts`

- [ ] **Step 1: Write the failing tests**

Append to `src/core/config.test.ts` (the `yaml` symbol is already imported there at line 2):

```ts
describe('generateServerConfig — dbPolicy', () => {
  it('omits policies.db when dbPolicy is not set (agentsh applies its own defaults)', () => {
    const result = generateServerConfig({});
    const parsed = yaml.load(result) as any;
    expect(parsed.policies).not.toHaveProperty('db');
  });

  it('emits only the fields the user set', () => {
    const result = generateServerConfig({
      dbPolicy: { logStatements: 'full' },
    });
    const parsed = yaml.load(result) as any;
    expect(parsed.policies.db).toEqual({ log_statements: 'full' });
  });

  it('emits all six fields when fully populated', () => {
    const result = generateServerConfig({
      dbPolicy: {
        logStatements: 'parameters_redacted',
        approvalStatementPreview: 'full',
        approvalStatementPreviewChars: 500,
        unavoidability: 'required',
        escalateUnknownFunctions: true,
        safeFunctionAllowlist: ['lower', 'upper', 'now'],
      },
    });
    const parsed = yaml.load(result) as any;
    expect(parsed.policies.db).toEqual({
      log_statements: 'parameters_redacted',
      approval_statement_preview: 'full',
      approval_statement_preview_chars: 500,
      unavoidability: 'required',
      escalate_unknown_functions: true,
      safe_function_allowlist: ['lower', 'upper', 'now'],
    });
  });

  it('omits safe_function_allowlist when empty', () => {
    const result = generateServerConfig({
      dbPolicy: { escalateUnknownFunctions: true, safeFunctionAllowlist: [] },
    });
    const parsed = yaml.load(result) as any;
    expect(parsed.policies.db.escalate_unknown_functions).toBe(true);
    expect(parsed.policies.db).not.toHaveProperty('safe_function_allowlist');
  });

  it('coexists with policySigning under the same policies block', () => {
    const result = generateServerConfig({
      dbPolicy: { logStatements: 'none' },
      policySigning: { mode: 'enforce', trustStore: '/etc/agentsh/keys' },
    });
    const parsed = yaml.load(result) as any;
    expect(parsed.policies.db).toEqual({ log_statements: 'none' });
    expect(parsed.policies.signing).toEqual({ mode: 'enforce', trust_store: '/etc/agentsh/keys' });
  });
});
```

- [ ] **Step 2: Run the tests; expect failures**

Run: `npx vitest run src/core/config.test.ts -t "generateServerConfig — dbPolicy"`
Expected: 5 failing tests

- [ ] **Step 3: Add `dbPolicy` to `ServerConfigOpts`**

In `src/core/config.ts`, locate the `ServerConfigOpts` interface declaration. Add this field alongside the other optional sections (the precise position doesn't matter; group it visually near `policySigning`):

```ts
  /**
   * Server-side defaults for the DB-access subsystem (agentsh v0.20+).
   * Emitted under `policies.db` in the generated server config. When
   * unset, agentsh applies its own defaults via applyDefaults*.
   */
  dbPolicy?: {
    logStatements?: 'none' | 'parameters_redacted' | 'full';
    approvalStatementPreview?: 'redacted' | 'full';
    approvalStatementPreviewChars?: number;
    unavoidability?: 'off' | 'required';
    escalateUnknownFunctions?: boolean;
    safeFunctionAllowlist?: string[];
  };
```

- [ ] **Step 4: Add the emit branch in `generateServerConfig`**

In `src/core/config.ts`, immediately after the `policySigning` emit block (currently at lines 621-629), add:

```ts
  // DB policy server-side defaults (v0.20+)
  if (opts.dbPolicy) {
    const policies = (config.policies as Record<string, unknown>) ?? {};
    const db: Record<string, unknown> = {};
    if (opts.dbPolicy.logStatements) db.log_statements = opts.dbPolicy.logStatements;
    if (opts.dbPolicy.approvalStatementPreview) db.approval_statement_preview = opts.dbPolicy.approvalStatementPreview;
    if (opts.dbPolicy.approvalStatementPreviewChars !== undefined) {
      db.approval_statement_preview_chars = opts.dbPolicy.approvalStatementPreviewChars;
    }
    if (opts.dbPolicy.unavoidability) db.unavoidability = opts.dbPolicy.unavoidability;
    if (opts.dbPolicy.escalateUnknownFunctions !== undefined) {
      db.escalate_unknown_functions = opts.dbPolicy.escalateUnknownFunctions;
    }
    if (opts.dbPolicy.safeFunctionAllowlist && opts.dbPolicy.safeFunctionAllowlist.length > 0) {
      db.safe_function_allowlist = opts.dbPolicy.safeFunctionAllowlist;
    }
    if (Object.keys(db).length > 0) {
      policies.db = db;
      config.policies = policies;
    }
  }
```

- [ ] **Step 5: Run the tests; expect passes**

Run: `npx vitest run src/core/config.test.ts -t "generateServerConfig — dbPolicy"`
Expected: 5 passing tests

- [ ] **Step 6: Run the full config test file**

Run: `npx vitest run src/core/config.test.ts`
Expected: all tests pass

- [ ] **Step 7: Run typecheck**

Run: `npm run typecheck`
Expected: clean

- [ ] **Step 8: Commit**

```bash
git add src/core/config.ts src/core/config.test.ts
git commit -m "$(cat <<'EOF'
feat(config): add dbPolicy to ServerConfigOpts

Adds dbPolicy optional block (logStatements, approvalStatementPreview,
approvalStatementPreviewChars, unavoidability, escalateUnknownFunctions,
safeFunctionAllowlist) emitted under policies.db with snake_case keys.
Coexists with policySigning under the same policies block. Omitted
entirely when unset so agentsh's applyDefaults* sets server-side
defaults.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 11: Update `docs/api.md` with Database access section

**Files:**
- Modify: `docs/api.md`

- [ ] **Step 1: Find a good insertion point**

Run: `grep -n "^## \|^### " docs/api.md | head -30`
Expected: a list of headings. Pick a logical location — typically immediately before or after the existing **HTTP services** section, since DB services are conceptually similar (proxied connections with policy).

- [ ] **Step 2: Add the Database access section**

Insert the following block at the chosen location:

````markdown
## Database access (v0.20+)

Agentsh v0.20+ introduces first-class policy for database connections and statements. Three new top-level keys in your `policy` and one new optional block in `serverConfig`:

- `policy.dbServices` — declare each database connection (family, dialect, upstream, TLS mode).
- `policy.databaseRules` — statement-level rules (which operations, against which schemas/objects, what decision).
- `policy.databaseConnectionRules` — connection-level rules (which users, applications, match kinds).
- `serverConfig.dbPolicy` — runtime defaults for statement logging, approval previews, and unavoidability.

For the full list of operation groups, aliases, subtypes, and resolution tags, see [agentsh's DB access spec](https://github.com/canyonroad/agentsh/blob/main/docs/db-access-spec.md). The TypeScript schema accepts any string for operations/subtypes so new agentsh additions don't require a library bump.

### Services (`policy.dbServices`)

A map of service name → connection definition.

```ts
import { secureSandbox } from '@agentsh/secure-sandbox';

const sandbox = await secureSandbox(adapter, {
  policy: {
    dbServices: {
      'pg-main': {
        family: 'postgres',
        dialect: 'postgres',
        upstream: '127.0.0.1:5432',
        tlsMode: 'terminate_reissue',     // required
        // optional flags:
        allowFunctionCallProtocol: false,
        allowGssEncryption: false,
        trustedNetwork: false,
      },
    },
  },
});
```

`tlsMode` is required. Valid values:

- `passthrough` — agentsh forwards the TLS stream without inspecting statements. Statement-level policy is unavailable; connection-level fields like `dbUser`/`database` are invisible.
- `terminate_reissue` — agentsh terminates client TLS, reissues TLS to upstream. Full visibility, statement policy supported.
- `terminate_plaintext_upstream` — agentsh terminates client TLS, talks plaintext to upstream. Requires loopback/private upstream OR `trustedNetwork: true`.

### Statement rules (`policy.databaseRules`)

A list of rules evaluated against each SQL statement.

```ts
policy: {
  dbServices: { 'pg-main': { /* ... */ } },
  databaseRules: [
    {
      name: 'allow-app-reads',
      dbService: 'pg-main',
      schemas: ['public'],
      operations: ['read'],       // required, non-empty
      decision: 'allow',          // required
    },
    {
      name: 'deny-dangerous',
      operations: ['DANGEROUS'],  // alias expands to schema_destroy + privilege + ...
      decision: 'deny',
    },
    {
      name: 'redirect-to-canonical',
      relations: ['public.users_old'],
      operations: ['read'],
      decision: 'redirect',
      redirect: { relation: 'public.users' },
    },
    {
      name: 'audit-bulk-export',
      operations: ['bulk_export'],
      decision: 'audit',
      acknowledgeAuditOnDangerous: true,
    },
  ],
},
```

Key fields:

- `operations` — required, non-empty. Open vocab: accepts canonical groups (`'read'`, `'write'`, `'schema_destroy'`, ...), aliases (`'READ'`, `'INSERT'`, `'DANGEROUS'`, `'*'`), or any string agentsh adds in the future. Editor autocomplete is provided via the `DbOperationGroup` and `DbOperationAlias` exported types.
- `decision` — required. One of `'allow' | 'deny' | 'approve' | 'audit' | 'redirect'`.
- `redirect.relation` — required when `decision: 'redirect'`. Library validates this at parse time.
- `matchObjectResolution` — optional. Controls which resolution tags this rule matches (`'qualified_syntactic'`, `'catalog_resolved'`, `'*'`, etc.).
- `denyModeInTx` — `'terminate'` (kill the connection) or `'rollback_then_continue'` (rollback the transaction, leave connection open). Only meaningful with `decision: 'deny'`.
- `acknowledgeAuditOnDangerous` — silence the warning when auditing a high-risk operation group instead of denying it.

### Connection rules (`policy.databaseConnectionRules`)

A list of rules evaluated at connection time.

```ts
policy: {
  databaseConnectionRules: [
    {
      name: 'allow-app-user',
      dbService: 'pg-main',
      matchKind: 'connect',           // 'connect' | 'cancel' | 'replication'
      dbUser: ['app'],
      database: 'production',
      decision: 'allow',
    },
    {
      name: 'deny-replication',
      matchKind: 'replication',
      decision: 'deny',
    },
  ],
},
```

Notes:

- `decision: 'redirect'` is **not** supported on connection rules (enforced by the type).
- `matchKind: 'cancel'` + `decision: 'approve'` is invalid (cancel is real-time and cannot be held for approval). The library rejects this combination at parse time.
- `dbUser`, `database`, `applicationName` are invisible when the matching service uses `tlsMode: 'passthrough'`; agentsh will reject rules that reference them in that case at server start.

### Runtime defaults (`serverConfig.dbPolicy`)

Tunes how agentsh handles DB events at runtime. All fields optional; agentsh applies its own defaults for anything you leave out.

```ts
const sandbox = await secureSandbox(adapter, {
  serverConfig: {
    dbPolicy: {
      logStatements: 'parameters_redacted',  // 'none' | 'parameters_redacted' | 'full'
      approvalStatementPreview: 'redacted',  // 'redacted' | 'full'
      approvalStatementPreviewChars: 200,
      unavoidability: 'off',                 // 'off' | 'required'
      escalateUnknownFunctions: false,
      safeFunctionAllowlist: ['lower', 'upper', 'now'],
    },
  },
});
```

### What the library validates vs. what agentsh validates

The TS schema catches local-property bugs at parse time:

- `databaseRules[].operations` must be non-empty.
- `databaseRules[].decision: 'redirect'` requires `redirect.relation`.
- `databaseConnectionRules[].decision: 'redirect'` is rejected (not a valid value).
- `databaseConnectionRules[].matchKind: 'cancel'` + `decision: 'approve'` is rejected.
- Duplicate rule names within either list are rejected.

The TS schema does **not** validate cross-rule or runtime-dependent constraints — those are deferred to agentsh's startup validator and surface as `ProvisioningError` when `secureSandbox()` is called. These include:

- `tlsMode: 'terminate_plaintext_upstream'` requires loopback/private upstream OR `trustedNetwork: true`.
- Catalog selectors (`relations`/`functions` with `matchObjectResolution: 'catalog_resolved'`) require a terminate-mode Postgres service.
- The "unsafe allow rule" check (`decision: 'allow'` + `operations: ['*']` without a service/family filter).
- Operation alias expansion correctness.
- Approval `timeout` ≤ 600s.
````

- [ ] **Step 3: Verify the file renders cleanly**

Run: `grep -c "## Database access" docs/api.md`
Expected: 1 (single occurrence — no accidental duplicate)

- [ ] **Step 4: Commit**

```bash
git add docs/api.md
git commit -m "$(cat <<'EOF'
docs(api): add Database access section for v0.20 DB bindings

User-facing docs for dbServices, databaseRules, databaseConnectionRules,
and serverConfig.dbPolicy. Worked examples for each rule type, the TLS
mode taxonomy, what the library validates vs. what agentsh validates,
and a link to the upstream agentsh DB spec for the canonical operation
list (rather than duplicating it here).

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 12: Update `docs/SPEC-v2.md` with the schema reference

**Files:**
- Modify: `docs/SPEC-v2.md`

- [ ] **Step 1: Find a good insertion point**

Run: `grep -n "^## \|^### " docs/SPEC-v2.md | head -30`
Expected: a list of schema sections. Append the new `## Database` section at the appropriate place (typically near other policy schema sections).

- [ ] **Step 2: Add the Database schema reference**

Insert the following block:

````markdown
## Database (v0.20+)

Bindings for agentsh v0.20's database-access subsystem. Three keys under `PolicyDefinition` and one under `ServerConfigOpts`.

### `PolicyDefinition.dbServices: Record<string, DbServiceDef>`

| Field | Type | YAML key | Required | Notes |
|---|---|---|---|---|
| `family` | `string` | `family` | yes | e.g. `'postgres'`, `'mysql'`, `'mongo'` |
| `dialect` | `string` | `dialect` | yes | e.g. `'postgres'`, `'aurora_postgres'`, `'redshift'` |
| `upstream` | `string` | `upstream` | yes | `host:port` |
| `tlsMode` | `'passthrough' \| 'terminate_reissue' \| 'terminate_plaintext_upstream'` | `tls_mode` | yes | |
| `allowFunctionCallProtocol` | `boolean` | `allow_function_call_protocol` | no | |
| `allowGssEncryption` | `boolean` | `allow_gss_encryption` | no | |
| `trustedNetwork` | `boolean` | `trusted_network` | no | Required when `tlsMode: 'terminate_plaintext_upstream'` to a non-loopback/private host |

Unknown fields preserved via `.passthrough()` for forward compatibility.

### `PolicyDefinition.databaseRules: DatabaseRule[]`

| Field | Type | YAML key | Required | Notes |
|---|---|---|---|---|
| `name` | `string` | `name` | yes | unique within the list |
| `operations` | `string[]` | `operations` | yes | non-empty; open vocab (see `DbOperationGroup`/`DbOperationAlias`) |
| `decision` | `'allow' \| 'deny' \| 'approve' \| 'audit' \| 'redirect'` | `decision` | yes | |
| `dbService` | `string` | `db_service` | no | service name filter |
| `dbFamily` | `string` | `db_family` | no | |
| `dbDialect` | `string` | `db_dialect` | no | |
| `schemas` | `string[]` | `schemas` | no | glob patterns |
| `objects` | `string[]` | `objects` | no | syntactic object name globs |
| `relations` | `string[]` | `relations` | no | canonical `schema.name` globs |
| `functions` | `string[]` | `functions` | no | canonical function identity globs |
| `subtypes` | `string[]` | `subtypes` | no | open vocab |
| `matchObjectResolution` | `'qualified_syntactic' \| 'unqualified_syntactic' \| 'ambiguous_after_search_path' \| 'maybe_temp_shadowed' \| 'unresolved' \| 'catalog_resolved' \| '*'` | `match_object_resolution` | no | |
| `message` | `string` | `message` | no | template (`{{.Operation}}` etc.) |
| `timeout` | `string` | `timeout` | no | duration; agentsh caps at 600s |
| `redirect` | `{ relation: string }` | `redirect` | required when `decision: 'redirect'` | |
| `acknowledgeAuditOnDangerous` | `boolean` | `acknowledge_audit_on_dangerous` | no | |
| `denyModeInTx` | `'terminate' \| 'rollback_then_continue'` | `deny_mode_in_tx` | no | meaningful with `decision: 'deny'` |

### `PolicyDefinition.databaseConnectionRules: DatabaseConnectionRule[]`

| Field | Type | YAML key | Required | Notes |
|---|---|---|---|---|
| `name` | `string` | `name` | yes | unique within the list |
| `decision` | `'allow' \| 'deny' \| 'approve' \| 'audit'` | `decision` | yes | `'redirect'` is **not** valid here |
| `dbService` | `string` | `db_service` | no | |
| `matchKind` | `'connect' \| 'cancel' \| 'replication'` | `match_kind` | no | defaults to `'connect'` server-side |
| `dbUser` | `string[]` | `db_user` | no | invisible under `tlsMode: 'passthrough'` |
| `database` | `string` | `database` | no | invisible under `tlsMode: 'passthrough'` |
| `applicationName` | `string` | `application_name` | no | invisible under `tlsMode: 'passthrough'` |
| `clientIdentity` | `string` | `client_identity` | no | visible across all TLS modes |
| `message` | `string` | `message` | no | |
| `timeout` | `string` | `timeout` | no | |

Validation: `matchKind: 'cancel'` + `decision: 'approve'` is rejected at parse time.

### `ServerConfigOpts.dbPolicy`

Emitted under `policies.db` in the generated server config. Omitted entirely when unset.

| Field | Type | YAML key | Notes |
|---|---|---|---|
| `logStatements` | `'none' \| 'parameters_redacted' \| 'full'` | `log_statements` | agentsh default: `'parameters_redacted'` |
| `approvalStatementPreview` | `'redacted' \| 'full'` | `approval_statement_preview` | |
| `approvalStatementPreviewChars` | `number` | `approval_statement_preview_chars` | agentsh default: `200` |
| `unavoidability` | `'off' \| 'required'` | `unavoidability` | agentsh default: `'off'` |
| `escalateUnknownFunctions` | `boolean` | `escalate_unknown_functions` | agentsh default: `false` |
| `safeFunctionAllowlist` | `string[]` | `safe_function_allowlist` | meaningful with `escalateUnknownFunctions: true` |
````

- [ ] **Step 3: Commit**

```bash
git add docs/SPEC-v2.md
git commit -m "$(cat <<'EOF'
docs(spec): add DB schema reference for v0.20 bindings

Schema reference tables for dbServices, databaseRules,
databaseConnectionRules, and dbPolicy with TS type, YAML key, required
flag, and notes for each field. Complements the user-facing prose in
docs/api.md.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 13: Final verification

**Files:**
- (none modified)

- [ ] **Step 1: Full unit test run**

Run: `npm test`
Expected: ~700+ tests passing (646 baseline + the new DB tests added across Tasks 2–10), 16 test files. Specifically, you should see:
- `src/policies/schema.test.ts` — original tests + DB acceptance + DB validation tests
- `src/policies/serialize.test.ts` — original tests + 3 new `serializePolicy — db*` describes
- `src/core/config.test.ts` — original tests + 1 new `generateServerConfig — dbPolicy` describe

- [ ] **Step 2: Typecheck**

Run: `npm run typecheck`
Expected: clean

- [ ] **Step 3: Build**

Run: `npm run build`
Expected: clean build (artifact in `dist/`)

- [ ] **Step 4: Quick smoke check on the exports**

Run: `node -e "const m = require('./dist/policies/schema.js'); console.log(Object.keys(m).filter(k => k.startsWith('Db') || k.startsWith('Database')))"`
Expected: list includes `DbServiceDefSchema`, `DatabaseRuleSchema`, `DatabaseConnectionRuleSchema`. (The hint unions `DbOperationGroup` / `DbOperationAlias` are TS-only types and won't appear at runtime.)

- [ ] **Step 5: Verify all commits are clean**

Run: `git log --oneline -15`
Expected: a clear sequence of commits matching Tasks 2–12, each prefixed with `feat(schema):`, `feat(serialize):`, `feat(config):`, or `docs(...)`.

- [ ] **Step 6: Verify no stray uncommitted files from this work**

Run: `git status -s`
Expected: only files unrelated to this plan (e.g., the in-flight v0.20.0 bump if still uncommitted, but no DB-related modifications).

If everything checks out, this sub-project is ready for review/merge.

---

## What this plan deliberately does NOT do

- No changes to any adapter `*Defaults()` (per spec — agentsh's `applyDefaults*` handles server-side DB defaults).
- No new e2e tests (no downstream user has a database wired in yet; integration coverage will come later when one does).
- No drift audit of non-DB existing fields (separate sub-project F).
- No bindings for any other v0.20 subsystem (audit/auth/sandbox/etc. are separate sub-projects B/C/D/E).
- No operation-alias expansion or runtime semantics in TypeScript (defer to agentsh — would drift on every agentsh release).
