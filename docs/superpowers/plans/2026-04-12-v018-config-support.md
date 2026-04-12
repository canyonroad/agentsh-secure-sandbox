# v0.18.0 Configuration Support Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add TypeScript types, Zod validation, and YAML serialization for three agentsh v0.18.0 features: `fuse.enabled`, audit integrity, and HTTP services (with integrated credential substitution and secret providers).

**Architecture:** All changes extend existing modules following the established pattern: types in `schema.ts`/`config.ts`, serialization in `serialize.ts`/`config.ts`, validation via Zod schemas. No new files created.

**Tech Stack:** TypeScript, Zod, js-yaml, Vitest

---

## File Map

| File | Action | Responsibility |
|------|--------|----------------|
| `src/core/config.ts` | Modify | Add `fuse.enabled` and `audit.integrity` to `ServerConfigOpts` + `generateServerConfig` |
| `src/core/config.test.ts` | Modify | Tests for fuse.enabled and audit integrity YAML output |
| `src/policies/schema.ts` | Modify | Add Zod schemas for secret providers, HTTP services (with credentials) |
| `src/policies/schema.test.ts` | Modify | Validation tests for new schemas |
| `src/policies/serialize.ts` | Modify | Add serializers for providers, HTTP services |
| `src/policies/serialize.test.ts` | Modify | Serialization tests for new policy sections |
| `src/policies/index.ts` | Modify | Re-export new types |

---

### Task 1: `fuse.enabled` in ServerConfigOpts

**Files:**
- Modify: `src/core/config.ts:16` (fuse type)
- Modify: `src/core/config.ts:213-218` (generateServerConfig fuse block)
- Test: `src/core/config.test.ts`

- [ ] **Step 1: Write the failing test**

Add to the `generateServerConfig -- extended fields` describe block in `src/core/config.test.ts`:

```typescript
it('sets fuse.enabled when explicitly set to true', () => {
  const result = generateServerConfig({ fuse: { enabled: true } });
  const parsed = yaml.load(result) as any;
  expect(parsed.sandbox.fuse.enabled).toBe(true);
});

it('keeps fuse.enabled false by default even when other fuse opts are set', () => {
  const result = generateServerConfig({ fuse: { deferred: true } });
  const parsed = yaml.load(result) as any;
  expect(parsed.sandbox.fuse.enabled).toBe(false);
  expect(parsed.sandbox.fuse.deferred).toBe(true);
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run src/core/config.test.ts --reporter=verbose`
Expected: First test FAILS — `fuse.enabled` stays `false` even when `{ enabled: true }` is passed.

- [ ] **Step 3: Add `enabled` to the fuse type in ServerConfigOpts**

In `src/core/config.ts`, change the `fuse` field in `ServerConfigOpts` (line 16):

```typescript
fuse?: { enabled?: boolean; deferred?: boolean; deferredMarkerFile?: string; deferredEnableCommand?: string[] };
```

- [ ] **Step 4: Wire `fuse.enabled` into generateServerConfig**

In `src/core/config.ts`, in the `if (opts.fuse)` block (around line 213), add the `enabled` line before the existing `deferred` line:

```typescript
if (opts.fuse) {
  const fuseObj = (config.sandbox as any).fuse;
  if (opts.fuse.enabled !== undefined) fuseObj.enabled = opts.fuse.enabled;
  if (opts.fuse.deferred !== undefined) fuseObj.deferred = opts.fuse.deferred;
  if (opts.fuse.deferredMarkerFile) fuseObj.deferred_marker_file = opts.fuse.deferredMarkerFile;
  if (opts.fuse.deferredEnableCommand) fuseObj.deferred_enable_command = opts.fuse.deferredEnableCommand;
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `npx vitest run src/core/config.test.ts --reporter=verbose`
Expected: All tests PASS including the two new ones.

- [ ] **Step 6: Commit**

```bash
git add src/core/config.ts src/core/config.test.ts
git commit -m "feat: expose fuse.enabled in ServerConfigOpts"
```

---

### Task 2: Audit Integrity (HMAC chain) in ServerConfigOpts

**Files:**
- Modify: `src/core/config.ts:13` (audit type in ServerConfigOpts)
- Modify: `src/core/config.ts:190-201` (generateServerConfig audit block)
- Test: `src/core/config.test.ts`

- [ ] **Step 1: Write the failing tests**

Add to the `generateServerConfig -- extended fields` describe block in `src/core/config.test.ts`:

```typescript
it('generates audit.integrity with file key source', () => {
  const result = generateServerConfig({
    audit: {
      enabled: true,
      sqlitePath: '/var/audit.db',
      integrity: {
        enabled: true,
        algorithm: 'hmac-sha256',
        keySource: 'file',
        keyFile: '/etc/agentsh/hmac.key',
      },
    },
  });
  const parsed = yaml.load(result) as any;
  expect(parsed.audit.enabled).toBe(true);
  expect(parsed.audit.integrity.enabled).toBe(true);
  expect(parsed.audit.integrity.algorithm).toBe('hmac-sha256');
  expect(parsed.audit.integrity.key_source).toBe('file');
  expect(parsed.audit.integrity.key_file).toBe('/etc/agentsh/hmac.key');
});

it('generates audit.integrity with env key source', () => {
  const result = generateServerConfig({
    audit: {
      integrity: {
        enabled: true,
        algorithm: 'hmac-sha512',
        keySource: 'env',
        keyEnv: 'HMAC_KEY',
      },
    },
  });
  const parsed = yaml.load(result) as any;
  expect(parsed.audit.integrity.algorithm).toBe('hmac-sha512');
  expect(parsed.audit.integrity.key_source).toBe('env');
  expect(parsed.audit.integrity.key_env).toBe('HMAC_KEY');
});

it('generates audit.integrity with aws_kms key source', () => {
  const result = generateServerConfig({
    audit: {
      integrity: {
        enabled: true,
        keySource: 'aws_kms',
        awsKms: { keyId: 'alias/my-key', region: 'us-east-1', encryptedDekFile: '/var/lib/agentsh/dek.enc' },
      },
    },
  });
  const parsed = yaml.load(result) as any;
  expect(parsed.audit.integrity.key_source).toBe('aws_kms');
  expect(parsed.audit.integrity.aws_kms).toEqual({
    key_id: 'alias/my-key',
    region: 'us-east-1',
    encrypted_dek_file: '/var/lib/agentsh/dek.enc',
  });
});

it('generates audit.integrity with azure_keyvault key source', () => {
  const result = generateServerConfig({
    audit: {
      integrity: {
        enabled: true,
        keySource: 'azure_keyvault',
        azureKeyVault: { vaultUrl: 'https://myvault.vault.azure.net', keyName: 'hmac-key', keyVersion: 'v1' },
      },
    },
  });
  const parsed = yaml.load(result) as any;
  expect(parsed.audit.integrity.key_source).toBe('azure_keyvault');
  expect(parsed.audit.integrity.azure_keyvault).toEqual({
    vault_url: 'https://myvault.vault.azure.net',
    key_name: 'hmac-key',
    key_version: 'v1',
  });
});

it('generates audit.integrity with hashicorp_vault key source', () => {
  const result = generateServerConfig({
    audit: {
      integrity: {
        enabled: true,
        keySource: 'hashicorp_vault',
        hashicorpVault: {
          address: 'https://vault.internal',
          authMethod: 'kubernetes',
          kubernetesRole: 'agentsh',
          secretPath: 'secret/data/agentsh/audit-key',
          keyField: 'key',
        },
      },
    },
  });
  const parsed = yaml.load(result) as any;
  expect(parsed.audit.integrity.key_source).toBe('hashicorp_vault');
  expect(parsed.audit.integrity.hashicorp_vault).toEqual({
    address: 'https://vault.internal',
    auth_method: 'kubernetes',
    kubernetes_role: 'agentsh',
    secret_path: 'secret/data/agentsh/audit-key',
    key_field: 'key',
  });
});

it('generates audit.integrity with gcp_kms key source', () => {
  const result = generateServerConfig({
    audit: {
      integrity: {
        enabled: true,
        keySource: 'gcp_kms',
        gcpKms: {
          keyName: 'projects/my-project/locations/us-east1/keyRings/agentsh/cryptoKeys/audit',
          encryptedDekFile: '/var/lib/agentsh/dek.enc',
        },
      },
    },
  });
  const parsed = yaml.load(result) as any;
  expect(parsed.audit.integrity.key_source).toBe('gcp_kms');
  expect(parsed.audit.integrity.gcp_kms).toEqual({
    key_name: 'projects/my-project/locations/us-east1/keyRings/agentsh/cryptoKeys/audit',
    encrypted_dek_file: '/var/lib/agentsh/dek.enc',
  });
});

it('omits audit.integrity when not set', () => {
  const result = generateServerConfig({ audit: { enabled: true } });
  const parsed = yaml.load(result) as any;
  expect(parsed.audit.integrity).toBeUndefined();
});

it('omits optional integrity fields when not provided', () => {
  const result = generateServerConfig({
    audit: {
      integrity: {
        enabled: true,
        keySource: 'aws_kms',
        awsKms: { keyId: 'alias/my-key', region: 'us-east-1' },
      },
    },
  });
  const parsed = yaml.load(result) as any;
  expect(parsed.audit.integrity.aws_kms.encrypted_dek_file).toBeUndefined();
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run src/core/config.test.ts --reporter=verbose`
Expected: All 8 new tests FAIL.

- [ ] **Step 3: Add `integrity` to the audit type in ServerConfigOpts**

In `src/core/config.ts`, extend the `audit` field in `ServerConfigOpts`:

```typescript
audit?: {
  enabled?: boolean;
  sqlitePath?: string;
  batchSize?: number;
  flushInterval?: string;
  channelSize?: number;
  integrity?: {
    enabled?: boolean;
    algorithm?: 'hmac-sha256' | 'hmac-sha512';
    keySource?: 'file' | 'env' | 'aws_kms' | 'azure_keyvault' | 'hashicorp_vault' | 'gcp_kms';
    keyFile?: string;
    keyEnv?: string;
    awsKms?: { keyId: string; region: string; encryptedDekFile?: string };
    azureKeyVault?: { vaultUrl: string; keyName: string; keyVersion?: string };
    hashicorpVault?: {
      address: string;
      authMethod?: string;
      tokenFile?: string;
      kubernetesRole?: string;
      approleId?: string;
      secretId?: string;
      secretPath: string;
      keyField?: string;
    };
    gcpKms?: { keyName: string; encryptedDekFile?: string };
  };
};
```

- [ ] **Step 4: Wire integrity serialization into generateServerConfig**

In `src/core/config.ts`, at the end of the `if (opts.audit)` block, before `config.audit = auditObj;`:

```typescript
if (opts.audit.integrity) {
  const integ: Record<string, unknown> = {};
  if (opts.audit.integrity.enabled !== undefined) integ.enabled = opts.audit.integrity.enabled;
  if (opts.audit.integrity.algorithm) integ.algorithm = opts.audit.integrity.algorithm;
  if (opts.audit.integrity.keySource) integ.key_source = opts.audit.integrity.keySource;
  if (opts.audit.integrity.keyFile) integ.key_file = opts.audit.integrity.keyFile;
  if (opts.audit.integrity.keyEnv) integ.key_env = opts.audit.integrity.keyEnv;
  if (opts.audit.integrity.awsKms) {
    integ.aws_kms = {
      key_id: opts.audit.integrity.awsKms.keyId,
      region: opts.audit.integrity.awsKms.region,
      ...(opts.audit.integrity.awsKms.encryptedDekFile && { encrypted_dek_file: opts.audit.integrity.awsKms.encryptedDekFile }),
    };
  }
  if (opts.audit.integrity.azureKeyVault) {
    integ.azure_keyvault = {
      vault_url: opts.audit.integrity.azureKeyVault.vaultUrl,
      key_name: opts.audit.integrity.azureKeyVault.keyName,
      ...(opts.audit.integrity.azureKeyVault.keyVersion && { key_version: opts.audit.integrity.azureKeyVault.keyVersion }),
    };
  }
  if (opts.audit.integrity.hashicorpVault) {
    const hv = opts.audit.integrity.hashicorpVault;
    integ.hashicorp_vault = {
      address: hv.address,
      secret_path: hv.secretPath,
      ...(hv.authMethod && { auth_method: hv.authMethod }),
      ...(hv.tokenFile && { token_file: hv.tokenFile }),
      ...(hv.kubernetesRole && { kubernetes_role: hv.kubernetesRole }),
      ...(hv.approleId && { approle_id: hv.approleId }),
      ...(hv.secretId && { secret_id: hv.secretId }),
      ...(hv.keyField && { key_field: hv.keyField }),
    };
  }
  if (opts.audit.integrity.gcpKms) {
    integ.gcp_kms = {
      key_name: opts.audit.integrity.gcpKms.keyName,
      ...(opts.audit.integrity.gcpKms.encryptedDekFile && { encrypted_dek_file: opts.audit.integrity.gcpKms.encryptedDekFile }),
    };
  }
  auditObj.integrity = integ;
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `npx vitest run src/core/config.test.ts --reporter=verbose`
Expected: All tests PASS.

- [ ] **Step 6: Commit**

```bash
git add src/core/config.ts src/core/config.test.ts
git commit -m "feat: add audit integrity (HMAC chain) to ServerConfigOpts"
```

---

### Task 3: Secret Providers Zod Schema + Serialization

**Files:**
- Modify: `src/policies/schema.ts` (add provider schemas)
- Modify: `src/policies/serialize.ts` (add provider serializer)
- Test: `src/policies/schema.test.ts`, `src/policies/serialize.test.ts`

- [ ] **Step 1: Write the failing schema tests**

Add to `src/policies/schema.test.ts`:

```typescript
// ─── providers (secret providers) ─────────────────────────

it('accepts providers with keyring type', () => {
  const result = PolicyDefinitionSchema.safeParse({
    providers: { local: { type: 'keyring' } },
  });
  expect(result.success).toBe(true);
});

it('accepts providers with vault type and auth', () => {
  const result = PolicyDefinitionSchema.safeParse({
    providers: {
      myVault: {
        type: 'vault',
        address: 'https://vault.internal',
        namespace: 'team-a',
        auth: { method: 'token', tokenRef: 'keyring://agentsh/vault-token' },
      },
    },
  });
  expect(result.success).toBe(true);
});

it('accepts vault provider with approle auth', () => {
  const result = PolicyDefinitionSchema.safeParse({
    providers: {
      v: {
        type: 'vault',
        address: 'https://vault.internal',
        auth: { method: 'approle', roleId: 'r1', secretIdRef: 'keyring://agentsh/sid' },
      },
    },
  });
  expect(result.success).toBe(true);
});

it('accepts vault provider with kubernetes auth', () => {
  const result = PolicyDefinitionSchema.safeParse({
    providers: {
      v: {
        type: 'vault',
        address: 'https://vault.internal',
        auth: { method: 'kubernetes', kubeRole: 'agentsh', kubeMountPath: 'kubernetes', kubeTokenPath: '/var/run/secrets/kubernetes.io/serviceaccount/token' },
      },
    },
  });
  expect(result.success).toBe(true);
});

it('accepts providers with aws-sm type', () => {
  const result = PolicyDefinitionSchema.safeParse({
    providers: { aws: { type: 'aws-sm', region: 'us-east-1' } },
  });
  expect(result.success).toBe(true);
});

it('accepts providers with gcp-sm type', () => {
  const result = PolicyDefinitionSchema.safeParse({
    providers: { gcp: { type: 'gcp-sm', projectId: 'my-project' } },
  });
  expect(result.success).toBe(true);
});

it('accepts providers with azure-kv type', () => {
  const result = PolicyDefinitionSchema.safeParse({
    providers: { azure: { type: 'azure-kv', vaultUrl: 'https://myvault.vault.azure.net' } },
  });
  expect(result.success).toBe(true);
});

it('accepts providers with op type', () => {
  const result = PolicyDefinitionSchema.safeParse({
    providers: { onepass: { type: 'op', serverUrl: 'https://op.internal', apiKeyRef: 'keyring://agentsh/op_key' } },
  });
  expect(result.success).toBe(true);
});

it('accepts multiple providers', () => {
  const result = PolicyDefinitionSchema.safeParse({
    providers: {
      kr: { type: 'keyring' },
      aws: { type: 'aws-sm', region: 'us-east-1' },
      v: { type: 'vault', address: 'https://vault.internal' },
    },
  });
  expect(result.success).toBe(true);
});

it('rejects provider with unknown type', () => {
  const result = PolicyDefinitionSchema.safeParse({
    providers: { bad: { type: 'unknown-type' } },
  });
  expect(result.success).toBe(false);
});

it('rejects vault provider without required address', () => {
  const result = PolicyDefinitionSchema.safeParse({
    providers: { bad: { type: 'vault' } },
  });
  expect(result.success).toBe(false);
});

it('rejects aws-sm provider without required region', () => {
  const result = PolicyDefinitionSchema.safeParse({
    providers: { bad: { type: 'aws-sm' } },
  });
  expect(result.success).toBe(false);
});

it('rejects op provider without required serverUrl', () => {
  const result = PolicyDefinitionSchema.safeParse({
    providers: { bad: { type: 'op' } },
  });
  expect(result.success).toBe(false);
});

it('accepts empty providers map', () => {
  const result = PolicyDefinitionSchema.safeParse({ providers: {} });
  expect(result.success).toBe(true);
});
```

- [ ] **Step 2: Write the failing serialization tests**

Add to `src/policies/serialize.test.ts`:

```typescript
// ─── providers (secret providers) ─────────────────────────

it('serializes providers with multiple types', () => {
  const result = serializePolicy({
    providers: {
      local: { type: 'keyring' },
      aws: { type: 'aws-sm', region: 'us-east-1' },
      myVault: {
        type: 'vault',
        address: 'https://vault.internal',
        namespace: 'ns',
        auth: { method: 'token', tokenRef: 'keyring://agentsh/vt' },
      },
    },
  });
  const parsed = yaml.load(result) as any;
  expect(parsed.providers.local).toEqual({ type: 'keyring' });
  expect(parsed.providers.aws).toEqual({ type: 'aws-sm', region: 'us-east-1' });
  expect(parsed.providers.myVault).toEqual({
    type: 'vault',
    address: 'https://vault.internal',
    namespace: 'ns',
    auth: { method: 'token', token_ref: 'keyring://agentsh/vt' },
  });
});

it('serializes gcp-sm provider with snake_case', () => {
  const result = serializePolicy({
    providers: { gcp: { type: 'gcp-sm', projectId: 'my-project' } },
  });
  const parsed = yaml.load(result) as any;
  expect(parsed.providers.gcp).toEqual({ type: 'gcp-sm', project_id: 'my-project' });
});

it('serializes azure-kv provider with snake_case', () => {
  const result = serializePolicy({
    providers: { azure: { type: 'azure-kv', vaultUrl: 'https://myvault.vault.azure.net' } },
  });
  const parsed = yaml.load(result) as any;
  expect(parsed.providers.azure).toEqual({ type: 'azure-kv', vault_url: 'https://myvault.vault.azure.net' });
});

it('serializes op provider with snake_case', () => {
  const result = serializePolicy({
    providers: { onepass: { type: 'op', serverUrl: 'https://op.internal', apiKeyRef: 'keyring://agentsh/op_key' } },
  });
  const parsed = yaml.load(result) as any;
  expect(parsed.providers.onepass).toEqual({ type: 'op', server_url: 'https://op.internal', api_key_ref: 'keyring://agentsh/op_key' });
});

it('serializes vault provider with approle auth', () => {
  const result = serializePolicy({
    providers: {
      v: {
        type: 'vault',
        address: 'https://vault.internal',
        auth: { method: 'approle', roleId: 'r1', secretIdRef: 'keyring://agentsh/sid' },
      },
    },
  });
  const parsed = yaml.load(result) as any;
  expect(parsed.providers.v.auth).toEqual({ method: 'approle', role_id: 'r1', secret_id_ref: 'keyring://agentsh/sid' });
});

it('serializes vault provider with kubernetes auth', () => {
  const result = serializePolicy({
    providers: {
      v: {
        type: 'vault',
        address: 'https://vault.internal',
        auth: { method: 'kubernetes', kubeRole: 'agentsh', kubeMountPath: 'kubernetes' },
      },
    },
  });
  const parsed = yaml.load(result) as any;
  expect(parsed.providers.v.auth).toEqual({ method: 'kubernetes', kube_role: 'agentsh', kube_mount_path: 'kubernetes' });
});

it('omits providers when empty', () => {
  const result = serializePolicy({ providers: {} });
  const parsed = yaml.load(result) as any;
  expect(parsed.providers).toBeUndefined();
});

it('omits providers when not set', () => {
  const result = serializePolicy({ file: [{ allow: '/workspace/**' }] });
  const parsed = yaml.load(result) as any;
  expect(parsed.providers).toBeUndefined();
});
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `npx vitest run src/policies/schema.test.ts src/policies/serialize.test.ts --reporter=verbose`
Expected: All new tests FAIL.

- [ ] **Step 4: Add Zod schemas to schema.ts**

In `src/policies/schema.ts`, after the `UnixSocketRuleSchema` and before `ResourceLimitsSchema`, add:

```typescript
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
```

Add to `PolicyDefinitionSchema`:

```typescript
providers: z.record(z.string(), SecretProviderSchema).optional(),
```

Add type exports:

```typescript
export type VaultAuth = z.infer<typeof VaultAuthSchema>;
export type SecretProvider = z.infer<typeof SecretProviderSchema>;
```

- [ ] **Step 5: Add serializer to serialize.ts**

Add `SecretProvider` and `VaultAuth` to imports from `./schema.js`, then add:

```typescript
// ─── Secret providers ─────────────────────────────────────

function serializeVaultAuth(auth: VaultAuth): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  if (auth.method) out.method = auth.method;
  if (auth.token) out.token = auth.token;
  if (auth.tokenRef) out.token_ref = auth.tokenRef;
  if (auth.roleId) out.role_id = auth.roleId;
  if (auth.roleIdRef) out.role_id_ref = auth.roleIdRef;
  if (auth.secretId) out.secret_id = auth.secretId;
  if (auth.secretIdRef) out.secret_id_ref = auth.secretIdRef;
  if (auth.kubeRole) out.kube_role = auth.kubeRole;
  if (auth.kubeMountPath) out.kube_mount_path = auth.kubeMountPath;
  if (auth.kubeTokenPath) out.kube_token_path = auth.kubeTokenPath;
  return out;
}

function serializeProviders(providers: Record<string, SecretProvider>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [name, p] of Object.entries(providers)) {
    const entry: Record<string, unknown> = { type: p.type };
    switch (p.type) {
      case 'keyring':
        break;
      case 'vault':
        entry.address = p.address;
        if (p.namespace) entry.namespace = p.namespace;
        if (p.auth) entry.auth = serializeVaultAuth(p.auth);
        break;
      case 'aws-sm':
        entry.region = p.region;
        break;
      case 'gcp-sm':
        entry.project_id = p.projectId;
        break;
      case 'azure-kv':
        entry.vault_url = p.vaultUrl;
        break;
      case 'op':
        entry.server_url = p.serverUrl;
        if (p.apiKey) entry.api_key = p.apiKey;
        if (p.apiKeyRef) entry.api_key_ref = p.apiKeyRef;
        break;
    }
    out[name] = entry;
  }
  return out;
}
```

Wire into `serializePolicy`:

```typescript
if (policy.providers && Object.keys(policy.providers).length > 0) {
  doc.providers = serializeProviders(policy.providers);
}
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `npx vitest run src/policies/schema.test.ts src/policies/serialize.test.ts --reporter=verbose`
Expected: All tests PASS.

- [ ] **Step 7: Commit**

```bash
git add src/policies/schema.ts src/policies/schema.test.ts src/policies/serialize.ts src/policies/serialize.test.ts
git commit -m "feat: add secret providers schema and serialization"
```

---

### Task 4: HTTP Services Zod Schema + Serialization (with integrated credentials)

**Files:**
- Modify: `src/policies/schema.ts` (add HTTP service schemas)
- Modify: `src/policies/serialize.ts` (add HTTP service serializer)
- Test: `src/policies/schema.test.ts`, `src/policies/serialize.test.ts`

- [ ] **Step 1: Write the failing schema tests**

Add to `src/policies/schema.test.ts`:

```typescript
// ─── httpServices ──────────────────────────────────────────

it('accepts httpService with filtering rules only', () => {
  const result = PolicyDefinitionSchema.safeParse({
    httpServices: [{
      name: 'internal-api',
      upstream: 'https://api.internal.corp',
      default: 'deny',
      rules: [
        { name: 'read-only', methods: ['GET'], paths: ['/**'], decision: 'allow' },
      ],
    }],
  });
  expect(result.success).toBe(true);
});

it('accepts httpService with credentials and rules', () => {
  const result = PolicyDefinitionSchema.safeParse({
    httpServices: [{
      name: 'github',
      upstream: 'https://api.github.com',
      exposeAs: 'GITHUB_API_URL',
      aliases: ['api.github.com'],
      allowDirect: false,
      default: 'deny',
      secret: { ref: 'vault://kv/data/github#token', format: 'ghp_{rand:36}' },
      inject: { header: { name: 'Authorization', template: 'Bearer {{secret}}' } },
      scrubResponse: true,
      rules: [
        { name: 'read-issues', methods: ['GET'], paths: ['/repos/*/*/issues'], decision: 'allow' },
        { name: 'create-issue', methods: ['POST'], paths: ['/repos/*/*/issues'], decision: 'approve', message: 'Approve issue creation?', timeout: '5m' },
      ],
    }],
  });
  expect(result.success).toBe(true);
});

it('accepts httpService with credentials only (no rules)', () => {
  const result = PolicyDefinitionSchema.safeParse({
    httpServices: [{
      name: 'anthropic',
      upstream: 'https://api.anthropic.com',
      secret: { ref: 'keyring://agentsh/anthropic_key', format: 'sk-ant-{rand:93}' },
      inject: { header: { name: 'x-api-key', template: '{{secret}}' } },
    }],
  });
  expect(result.success).toBe(true);
});

it('accepts httpService with only required fields', () => {
  const result = PolicyDefinitionSchema.safeParse({
    httpServices: [{ name: 'minimal', upstream: 'https://api.example.com' }],
  });
  expect(result.success).toBe(true);
});

it('accepts all httpService rule decisions', () => {
  for (const decision of ['allow', 'deny', 'approve', 'audit'] as const) {
    const result = PolicyDefinitionSchema.safeParse({
      httpServices: [{
        name: `test-${decision}`,
        upstream: 'https://api.example.com',
        rules: [{ name: `rule-${decision}`, paths: ['/**'], decision }],
      }],
    });
    expect(result.success).toBe(true);
  }
});

it('rejects httpService rule without paths', () => {
  const result = PolicyDefinitionSchema.safeParse({
    httpServices: [{
      name: 'test',
      upstream: 'https://api.example.com',
      rules: [{ name: 'bad', decision: 'allow' }],
    }],
  });
  expect(result.success).toBe(false);
});

it('rejects httpService rule without name', () => {
  const result = PolicyDefinitionSchema.safeParse({
    httpServices: [{
      name: 'test',
      upstream: 'https://api.example.com',
      rules: [{ paths: ['/**'], decision: 'allow' }],
    }],
  });
  expect(result.success).toBe(false);
});

it('rejects httpService without name', () => {
  const result = PolicyDefinitionSchema.safeParse({
    httpServices: [{ upstream: 'https://api.example.com' }],
  });
  expect(result.success).toBe(false);
});

it('rejects httpService without upstream', () => {
  const result = PolicyDefinitionSchema.safeParse({
    httpServices: [{ name: 'test' }],
  });
  expect(result.success).toBe(false);
});

it('rejects httpService with invalid default', () => {
  const result = PolicyDefinitionSchema.safeParse({
    httpServices: [{ name: 'test', upstream: 'https://x.com', default: 'audit' }],
  });
  expect(result.success).toBe(false);
});

it('rejects httpService with unknown field', () => {
  const result = PolicyDefinitionSchema.safeParse({
    httpServices: [{ name: 'test', upstream: 'https://x.com', extra: true }],
  });
  expect(result.success).toBe(false);
});

it('accepts empty httpServices array', () => {
  const result = PolicyDefinitionSchema.safeParse({ httpServices: [] });
  expect(result.success).toBe(true);
});
```

- [ ] **Step 2: Write the failing serialization tests**

Add to `src/policies/serialize.test.ts`:

```typescript
// ─── httpServices ─────────────────────────────────────────

it('serializes httpService with credentials and rules', () => {
  const result = serializePolicy({
    httpServices: [{
      name: 'github',
      upstream: 'https://api.github.com',
      exposeAs: 'GITHUB_API_URL',
      aliases: ['api.github.com'],
      allowDirect: false,
      default: 'deny',
      secret: { ref: 'vault://kv/data/github#token', format: 'ghp_{rand:36}' },
      inject: { header: { name: 'Authorization', template: 'Bearer {{secret}}' } },
      scrubResponse: true,
      rules: [
        { name: 'read-issues', methods: ['GET'], paths: ['/repos/*/*/issues'], decision: 'allow' },
        { name: 'deny-rest', paths: ['/**'], decision: 'deny', message: 'Blocked' },
      ],
    }],
  });
  const parsed = yaml.load(result) as any;
  expect(parsed.http_services).toHaveLength(1);
  const svc = parsed.http_services[0];
  expect(svc.name).toBe('github');
  expect(svc.upstream).toBe('https://api.github.com');
  expect(svc.expose_as).toBe('GITHUB_API_URL');
  expect(svc.aliases).toEqual(['api.github.com']);
  expect(svc.allow_direct).toBe(false);
  expect(svc.default).toBe('deny');
  expect(svc.secret).toEqual({ ref: 'vault://kv/data/github#token', format: 'ghp_{rand:36}' });
  expect(svc.inject).toEqual({ header: { name: 'Authorization', template: 'Bearer {{secret}}' } });
  expect(svc.scrub_response).toBe(true);
  expect(svc.rules).toHaveLength(2);
  expect(svc.rules[0]).toEqual({ name: 'read-issues', methods: ['GET'], paths: ['/repos/*/*/issues'], decision: 'allow' });
  expect(svc.rules[1]).toEqual({ name: 'deny-rest', paths: ['/**'], decision: 'deny', message: 'Blocked' });
});

it('serializes httpService with only required fields', () => {
  const result = serializePolicy({
    httpServices: [{ name: 'minimal', upstream: 'https://api.example.com' }],
  });
  const parsed = yaml.load(result) as any;
  expect(parsed.http_services).toHaveLength(1);
  expect(parsed.http_services[0].name).toBe('minimal');
  expect(parsed.http_services[0].upstream).toBe('https://api.example.com');
  expect(parsed.http_services[0].expose_as).toBeUndefined();
  expect(parsed.http_services[0].rules).toBeUndefined();
  expect(parsed.http_services[0].secret).toBeUndefined();
});

it('serializes httpService rule with timeout', () => {
  const result = serializePolicy({
    httpServices: [{
      name: 'test',
      upstream: 'https://api.example.com',
      rules: [{ name: 'approve-it', methods: ['POST'], paths: ['/action'], decision: 'approve', timeout: '5m' }],
    }],
  });
  const parsed = yaml.load(result) as any;
  expect(parsed.http_services[0].rules[0].timeout).toBe('5m');
});

it('serializes credentials-only httpService', () => {
  const result = serializePolicy({
    httpServices: [{
      name: 'anthropic',
      upstream: 'https://api.anthropic.com',
      secret: { ref: 'keyring://agentsh/key', format: 'sk-ant-{rand:93}' },
      inject: { header: { name: 'x-api-key', template: '{{secret}}' } },
    }],
  });
  const parsed = yaml.load(result) as any;
  const svc = parsed.http_services[0];
  expect(svc.secret).toEqual({ ref: 'keyring://agentsh/key', format: 'sk-ant-{rand:93}' });
  expect(svc.inject).toEqual({ header: { name: 'x-api-key', template: '{{secret}}' } });
  expect(svc.rules).toBeUndefined();
});

it('omits http_services when httpServices is empty', () => {
  const result = serializePolicy({ httpServices: [] });
  const parsed = yaml.load(result) as any;
  expect(parsed.http_services).toBeUndefined();
});

it('omits http_services when not set', () => {
  const result = serializePolicy({ file: [{ allow: '/workspace/**' }] });
  const parsed = yaml.load(result) as any;
  expect(parsed.http_services).toBeUndefined();
});
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `npx vitest run src/policies/schema.test.ts src/policies/serialize.test.ts --reporter=verbose`
Expected: All new tests FAIL.

- [ ] **Step 4: Add Zod schemas to schema.ts**

In `src/policies/schema.ts`, after the `SecretProviderSchema`, add:

```typescript
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
```

Add to `PolicyDefinitionSchema`:

```typescript
httpServices: z.array(HttpServiceSchema).optional(),
```

Add type exports:

```typescript
export type HttpServiceSecret = z.infer<typeof HttpServiceSecretSchema>;
export type HttpServiceInjectHeader = z.infer<typeof HttpServiceInjectHeaderSchema>;
export type HttpServiceInject = z.infer<typeof HttpServiceInjectSchema>;
export type HttpServiceRule = z.infer<typeof HttpServiceRuleSchema>;
export type HttpService = z.infer<typeof HttpServiceSchema>;
```

- [ ] **Step 5: Add serializer to serialize.ts**

Add `HttpService` to imports from `./schema.js`, then add:

```typescript
// ─── HTTP services ────────────────────────────────────────

function serializeHttpServices(services: HttpService[]): Record<string, unknown>[] {
  return services.map((svc) => {
    const out: Record<string, unknown> = { name: svc.name, upstream: svc.upstream };
    if (svc.exposeAs) out.expose_as = svc.exposeAs;
    if (svc.aliases) out.aliases = svc.aliases;
    if (svc.allowDirect !== undefined) out.allow_direct = svc.allowDirect;
    if (svc.default) out.default = svc.default;
    if (svc.rules) {
      out.rules = svc.rules.map((rule) => {
        const r: Record<string, unknown> = {
          name: rule.name,
          paths: rule.paths,
          decision: rule.decision,
        };
        if (rule.methods) r.methods = rule.methods;
        if (rule.message) r.message = rule.message;
        if (rule.timeout) r.timeout = rule.timeout;
        return r;
      });
    }
    if (svc.secret) {
      out.secret = { ref: svc.secret.ref, format: svc.secret.format };
    }
    if (svc.inject) {
      const inj: Record<string, unknown> = {};
      if (svc.inject.header) {
        inj.header = { name: svc.inject.header.name, template: svc.inject.header.template };
      }
      out.inject = inj;
    }
    if (svc.scrubResponse !== undefined) out.scrub_response = svc.scrubResponse;
    return out;
  });
}
```

Wire into `serializePolicy`:

```typescript
if (policy.httpServices && policy.httpServices.length > 0) {
  doc.http_services = serializeHttpServices(policy.httpServices);
}
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `npx vitest run src/policies/schema.test.ts src/policies/serialize.test.ts --reporter=verbose`
Expected: All tests PASS.

- [ ] **Step 7: Commit**

```bash
git add src/policies/schema.ts src/policies/schema.test.ts src/policies/serialize.ts src/policies/serialize.test.ts
git commit -m "feat: add HTTP services with credential substitution schema and serialization"
```

---

### Task 5: Re-exports and Full Test Suite

**Files:**
- Modify: `src/policies/index.ts` (re-export new types)
- Test: run full test suite

- [ ] **Step 1: Update re-exports in policies/index.ts**

In `src/policies/index.ts`, update the type export line to include the new types:

```typescript
export type {
  PolicyDefinition,
  FileRule,
  NetworkRule,
  CommandRule,
  EnvRule,
  DnsRedirect,
  ConnectRedirect,
  SecretProvider,
  VaultAuth,
  HttpService,
  HttpServiceRule,
  HttpServiceSecret,
  HttpServiceInject,
  HttpServiceInjectHeader,
} from './schema.js';
```

Also export the new schemas:

```typescript
export { PolicyDefinitionSchema, HttpServiceSchema, SecretProviderSchema, validatePolicy } from './schema.js';
```

- [ ] **Step 2: Run the full unit test suite**

Run: `npx vitest run --reporter=verbose`
Expected: All tests PASS (existing + new). No regressions.

- [ ] **Step 3: Run type check**

Run: `npx tsc --noEmit`
Expected: No type errors.

- [ ] **Step 4: Commit**

```bash
git add src/policies/index.ts
git commit -m "feat: re-export new v0.18.0 policy types from policies index"
```
