# v0.18.0 Configuration Support

Add full TypeScript types, Zod validation, and YAML serialization for three agentsh v0.18.0 features not yet exposed in secure-sandbox.

## Scope

| Gap | Layer | Files |
|-----|-------|-------|
| `fuse.enabled` | Server config | `config.ts` |
| Audit integrity (HMAC chain) | Server config | `config.ts` |
| HTTP services (with integrated credential substitution) + secret providers | Policy schema | `schema.ts`, `serialize.ts` |

No new files. All changes extend existing modules. Public API shape unchanged -- users pass `serverConfig` and `policy` to `secureSandbox()` or provider defaults, same as today.

## Implementation order

1. `fuse.enabled` (no dependencies, one-liner)
2. Audit integrity (server config only)
3. Secret providers (policy schema + serialization)
4. HTTP services with credential substitution (policy schema + serialization, references providers)

---

## 1. `fuse.enabled`

`generateServerConfig` hardcodes `fuse: { enabled: false }`. The `fuse` option in `ServerConfigOpts` only exposes deferred-mode fields. Users cannot opt into FUSE.

### Changes

**`src/core/config.ts` -- `ServerConfigOpts.fuse`:**

```typescript
fuse?: {
  enabled?: boolean;  // NEW -- default: false
  deferred?: boolean;
  deferredMarkerFile?: string;
  deferredEnableCommand?: string[];
};
```

**`src/core/config.ts` -- `generateServerConfig`:**

Wire `opts.fuse.enabled` into the existing FUSE block, before the deferred logic:

```typescript
if (opts.fuse) {
  const fuseObj = (config.sandbox as any).fuse;
  if (opts.fuse.enabled !== undefined) fuseObj.enabled = opts.fuse.enabled;
  if (opts.fuse.deferred !== undefined) fuseObj.deferred = opts.fuse.deferred;
  // ... rest unchanged
}
```

Default stays `false` via the hardcoded baseline on line 135. Only explicit `fuse: { enabled: true }` enables it.

### Tests

Two unit tests: one confirming `fuse.enabled: true` appears when set, one confirming default stays false when other fuse opts are set.

---

## 2. Audit Integrity (HMAC Chain)

v0.18.0 can maintain an HMAC chain over audit log entries to detect tampering. Configured in server config, not policy.

### Types

**`src/core/config.ts` -- extend `ServerConfigOpts.audit`:**

The Go struct uses flat `key_file`/`key_env` fields (not nested objects) and each KMS provider has its own sub-config block with fields matching the Go structs exactly.

```typescript
audit?: {
  // existing
  enabled?: boolean;
  sqlitePath?: string;
  batchSize?: number;
  flushInterval?: string;
  channelSize?: number;
  // NEW
  integrity?: {
    enabled?: boolean;
    algorithm?: 'hmac-sha256' | 'hmac-sha512';
    keySource?: 'file' | 'env' | 'aws_kms' | 'azure_keyvault' | 'hashicorp_vault' | 'gcp_kms';
    // File/env sources (flat fields, not nested)
    keyFile?: string;        // path to HMAC key file
    keyEnv?: string;         // env var name containing the key
    // AWS KMS
    awsKms?: {
      keyId: string;         // KMS key ARN or alias
      region: string;
      encryptedDekFile?: string;
    };
    // Azure Key Vault
    azureKeyVault?: {
      vaultUrl: string;
      keyName: string;
      keyVersion?: string;
    };
    // HashiCorp Vault
    hashicorpVault?: {
      address: string;
      authMethod?: string;     // token | kubernetes | approle (default: token)
      tokenFile?: string;      // path to token file
      kubernetesRole?: string;
      approleId?: string;
      secretId?: string;
      secretPath: string;      // e.g. secret/data/agentsh/audit-key
      keyField?: string;       // field within secret (default: "key")
    };
    // GCP Cloud KMS
    gcpKms?: {
      keyName: string;         // full resource name
      encryptedDekFile?: string;
    };
  };
};
```

### Serialization

In the existing audit block of `generateServerConfig`, add integrity sub-object with camelCase-to-snake_case mapping:

- `keySource` -> `key_source`
- `keyFile` -> `key_file`
- `keyEnv` -> `key_env`
- `awsKms` -> `aws_kms` with `keyId` -> `key_id`, `encryptedDekFile` -> `encrypted_dek_file`
- `azureKeyVault` -> `azure_keyvault` with `vaultUrl` -> `vault_url`, `keyName` -> `key_name`, `keyVersion` -> `key_version`
- `hashicorpVault` -> `hashicorp_vault` with `authMethod` -> `auth_method`, `tokenFile` -> `token_file`, `kubernetesRole` -> `kubernetes_role`, `approleId` -> `approle_id`, `secretId` -> `secret_id`, `secretPath` -> `secret_path`, `keyField` -> `key_field`
- `gcpKms` -> `gcp_kms` with `keyName` -> `key_name`, `encryptedDekFile` -> `encrypted_dek_file`

### Defaults

None. Integrity is opt-in only.

### Tests

Unit tests for each key source variant producing correct YAML structure and snake_case field names.

---

## 3. Secret Providers

Policies can declare named secret providers that HTTP services reference via URI scheme. Each provider has a `type` field and type-specific config.

In the Go code, `Policy.Providers` is `map[string]yaml.Node` -- we model it as a typed discriminated union for the TypeScript layer.

### Types

**`src/policies/schema.ts` -- new Zod schemas:**

The vault provider has a complex `auth` block supporting token, approle, and kubernetes methods. The 1Password provider (`op`) supports chained refs via `apiKeyRef`.

```typescript
const VaultAuthSchema = z.object({
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
}).strict();

const SecretProviderSchema = z.discriminatedUnion('type', [
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

**`PolicyDefinitionSchema` -- add:**

```typescript
providers: z.record(z.string(), SecretProviderSchema).optional(),
```

### Serialization

Straightforward camelCase -> snake_case:

- `projectId` -> `project_id`
- `vaultUrl` -> `vault_url`
- `serverUrl` -> `server_url`
- `apiKey` -> `api_key`
- `apiKeyRef` -> `api_key_ref`
- Vault auth: `tokenRef` -> `token_ref`, `roleId` -> `role_id`, `roleIdRef` -> `role_id_ref`, `secretId` -> `secret_id`, `secretIdRef` -> `secret_id_ref`, `kubeRole` -> `kube_role`, `kubeMountPath` -> `kube_mount_path`, `kubeTokenPath` -> `kube_token_path`

### Tests

- Zod: each provider type validates, unknown type rejected, required fields enforced
- Serialization: providers map serializes with correct snake_case per type

---

## 4. HTTP Services (with integrated credential substitution)

v0.18.0 unifies HTTP service declarations with credential substitution. Each HTTP service can optionally carry `secret`, `inject`, and `scrub_response` fields directly -- there is no separate `services` array for credentials.

### Types

**`src/policies/schema.ts` -- new Zod schemas:**

```typescript
const HttpServiceSecretSchema = z.object({
  ref: z.string(),       // URI: vault://kv/data/github#token
  format: z.string(),    // fake template: ghp_{rand:36}
}).strict();

const HttpServiceInjectHeaderSchema = z.object({
  name: z.string(),      // header name, e.g. "Authorization"
  template: z.string(),  // e.g. "Bearer {{secret}}"
}).strict();

const HttpServiceInjectSchema = z.object({
  header: HttpServiceInjectHeaderSchema.optional(),
}).strict();

const HttpServiceRuleSchema = z.object({
  name: z.string(),
  methods: z.array(z.string()).optional(),
  paths: z.array(z.string()),               // required, at least one
  decision: z.enum(['allow', 'deny', 'approve', 'audit']),
  message: z.string().optional(),
  timeout: z.string().optional(),            // Go duration string
}).strict();

const HttpServiceSchema = z.object({
  name: z.string(),
  upstream: z.string(),
  exposeAs: z.string().optional(),
  aliases: z.array(z.string()).optional(),
  allowDirect: z.boolean().optional(),
  default: z.enum(['allow', 'deny']).optional(),
  rules: z.array(HttpServiceRuleSchema).optional(),
  // Credential substitution (optional)
  secret: HttpServiceSecretSchema.optional(),
  inject: HttpServiceInjectSchema.optional(),
  scrubResponse: z.boolean().optional(),
}).strict();
```

**`PolicyDefinitionSchema` -- add:**

```typescript
httpServices: z.array(HttpServiceSchema).optional(),
```

### Serialization

```typescript
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

### Usage example

```typescript
const policy: PolicyDefinition = {
  providers: {
    kr: { type: 'keyring' },
    myVault: { type: 'vault', address: 'https://vault.internal', auth: { method: 'token', tokenRef: 'keyring://agentsh/vault-token' } },
  },
  httpServices: [
    {
      name: 'github',
      upstream: 'https://api.github.com',
      default: 'deny',
      secret: { ref: 'vault://kv/data/github#token', format: 'ghp_{rand:36}' },
      inject: { header: { name: 'Authorization', template: 'Bearer {{secret}}' } },
      scrubResponse: true,
      rules: [
        { name: 'read-issues', methods: ['GET'], paths: ['/repos/*/*/issues'], decision: 'allow' },
        { name: 'deny-rest', paths: ['/**'], decision: 'deny' },
      ],
    },
    {
      name: 'internal-api',
      upstream: 'https://api.internal.corp',
      default: 'deny',
      rules: [
        { name: 'read-only', methods: ['GET'], paths: ['/**'], decision: 'allow' },
      ],
    },
  ],
};
```

### Tests

- Zod: full service with credentials, filtering-only service, credentials-only service
- Zod: rule without paths rejected, rule without name rejected
- Serialization: full service produces correct YAML with snake_case (expose_as, allow_direct, scrub_response)
- Serialization: service with only required fields omits optional keys

---

## Re-exports

Add new inferred types to the public API surface in `src/policies/index.ts`:

- `HttpService`, `HttpServiceRule`, `HttpServiceSecret`, `HttpServiceInject`, `HttpServiceInjectHeader` (from schema)
- `SecretProvider`, `VaultAuth` (from schema)

No new functions -- `serializePolicy` and `generateServerConfig` already handle everything.

---

## What this does NOT include

- Runtime validation that `secret.ref` URI scheme matches a declared provider -- this is a cross-field check better suited to a future `validatePolicySemantics()` pass, not the Zod schema layer.
- Runtime validation of `secret.format` template syntax (`{rand:N}` with N >= 24) -- enforced by agentsh at startup.
- New provider defaults -- all features are opt-in with no default configurations.
- E2E tests -- these features require provider-side infrastructure (vaults, KMS) that the E2E environments don't have. Unit tests cover types and serialization.
