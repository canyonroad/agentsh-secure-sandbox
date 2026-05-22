# API Reference

## `secureSandbox(adapter, config?)`

Secures any sandbox via its adapter. Returns a `SecuredSandbox` that mediates every command, file read, and file write through the [agentsh](https://www.agentsh.org) policy engine.

```typescript
import { secureSandbox } from '@agentsh/secure-sandbox';

const sandbox = await secureSandbox(adapter, {
  policy: agentDefault(),              // Policy to enforce (default: agentDefault())
  installStrategy: 'download',         // 'download' | 'upload' | 'preinstalled' | 'running'
  agentshVersion: '0.19.3',            // agentsh binary version
  minimumSecurityMode: 'landlock',     // Fail if kernel can't enforce this level
  threatFeeds: true,                   // Enable/disable/customize threat intelligence feeds
  packageChecks: {},                   // Enable package install security checks
});
```

### Config Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `policy` | `Policy` | `agentDefault()` | Policy rules for file, network, and command access |
| `installStrategy` | `string` | `'download'` | How to install the agentsh binary in the sandbox |
| `agentshVersion` | `string` | Library-pinned version | Pin a specific agentsh version |
| `minimumSecurityMode` | `SecurityMode` | `undefined` | Fail if the sandbox kernel can't enforce at least this level |
| `securityMode` | `SecurityMode` | `undefined` | Override detected security mode. Only used with `'running'` strategy (defaults to `'full'`). |
| `sessionId` | `string` | `undefined` | Existing agentsh session ID. Only used with `'running'` strategy. Falls back to `$AGENTSH_SESSION_ID`. |
| `threatFeeds` | `boolean \| ThreatFeedConfig` | `true` | Threat intelligence feed configuration |
| `packageChecks` | `false \| PackageChecksConfig` | `false` | Package install security checks (OSV, deps.dev, Socket, Snyk) |

### Install Strategies

| Strategy | When to Use |
|----------|-------------|
| `'download'` | Default — downloads agentsh from GitHub releases inside the sandbox |
| `'upload'` | Upload a local agentsh binary to the sandbox (useful for air-gapped environments) |
| `'preinstalled'` | agentsh is already installed in the sandbox image |
| `'running'` | agentsh is already running — skip installation and startup entirely |

## `SecuredSandbox`

The interface returned by `secureSandbox()`. Every operation is mediated by the policy engine.

```typescript
interface SecuredSandbox {
  exec(command: string, opts?: { cwd?: string; timeout?: number }): Promise<ExecResult>;
  writeFile(path: string, content: string): Promise<WriteFileResult>;
  readFile(path: string): Promise<ReadFileResult>;
  stop(): Promise<void>;
  readonly sessionId: string;
  readonly securityMode: SecurityMode;
}
```

### `exec(command, opts?)`

Run a shell command. The command is routed through the agentsh shell shim, which evaluates it against the policy before execution.

```typescript
const result = await sandbox.exec('npm install express');
// { stdout: '...', stderr: '...', exitCode: 0 }

const result = await sandbox.exec('cat .env');
// { stdout: '', stderr: 'denied by policy: file access blocked', exitCode: 126 }
```

### `writeFile(path, content)`

Write a file to the sandbox. File path is checked against file policy rules.

```typescript
await sandbox.writeFile('/workspace/index.js', 'console.log("hello")');
```

### `readFile(path)`

Read a file from the sandbox. File path is checked against file policy rules.

```typescript
const content = await sandbox.readFile('/workspace/index.js');
```

### `stop()`

Stop the sandbox and clean up resources.

### `sessionId`

Unique identifier for this secured sandbox session.

### `securityMode`

The actual security mode negotiated with the sandbox kernel. See [Security Modes](#security-modes).

## Security Modes

The security level depends on what the sandbox kernel supports. `secureSandbox()` automatically negotiates the highest available mode.

| Mode | Enforcement | Typical Platform |
|------|-------------|-----------------|
| `full` | seccomp + FUSE + Landlock + network proxy | Full Linux with FUSE support (E2B, Daytona, Blaxel, exe.dev) |
| `ptrace` | ptrace syscall interception + network proxy (exec, file, network, signal) | gVisor-based platforms (Modal) |
| `landlock` | Landlock + network proxy (no FUSE) | Firecracker VMs (Vercel, Cloudflare) |
| `landlock-only` | Landlock filesystem restrictions only | Limited kernel support |
| `minimal` | Per-command seccomp wrapper + network proxy + FUSE soft-delete + cgroups (no seccomp user-notify, no Landlock) | Kernels lacking Yama / user-notify support (Freestyle) |

> **Note:** seccomp and FUSE are disabled by default for compatibility. The detected security mode reflects kernel capabilities, not the active config. Landlock and network proxy are the default enforcement layers. Enable seccomp/FUSE explicitly via `serverConfig` if your environment supports them.

Use `minimumSecurityMode` to fail fast if the sandbox can't meet your security requirements:

```typescript
const sandbox = await secureSandbox(vercel(raw), {
  minimumSecurityMode: 'landlock', // Throws if kernel can't enforce this level
});

console.log(sandbox.securityMode); // 'landlock'
```

## Package Checks

Intercept package install commands (`npm install`, `pip install`, `yarn add`, etc.) and check packages against security providers before allowing installation. Disabled by default.

```typescript
const sandbox = await secureSandbox(vercel(raw), {
  packageChecks: {},  // Enable with free defaults (OSV, deps.dev, local)
});
```

### Configuration

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `scope` | `'new_packages_only' \| 'all_installs'` | `'new_packages_only'` | Check new packages only, or re-check on every install |
| `providers` | `Record<string, boolean \| ProviderConfig>` | 3 free defaults | Map of provider name to config |

### Default Providers

When enabled, three free providers are active:

| Provider | Priority | What It Checks |
|----------|----------|---------------|
| `local` | 0 | Local package metadata analysis |
| `osv` | 1 | Known vulnerabilities via [OSV.dev](https://osv.dev) |
| `depsdev` | 2 | License, scorecard, and dependency info via [deps.dev](https://deps.dev) |

### Adding Providers

```typescript
const sandbox = await secureSandbox(vercel(raw), {
  packageChecks: {
    providers: {
      socket: { apiKeyEnv: 'SOCKET_API_KEY' },  // Add Socket.dev
      snyk: { apiKeyEnv: 'SNYK_TOKEN' },         // Add Snyk
    },
  },
});
```

### Disabling a Default Provider

```typescript
const sandbox = await secureSandbox(vercel(raw), {
  packageChecks: {
    providers: { depsdev: false },  // Disable deps.dev
  },
});
```

### Provider Config

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | `boolean` | `true` | Enable/disable this provider |
| `priority` | `number` | varies | Lower = higher priority |
| `timeout` | `string` | provider default | Timeout duration (e.g. `'30s'`) |
| `onFailure` | `'warn' \| 'deny' \| 'allow' \| 'approve'` | provider default | Action when provider fails |
| `apiKeyEnv` | `string` | — | Environment variable holding the API key |
| `type` | `'exec'` | — | Provider type (use `'exec'` for custom command-based providers) |
| `command` | `string` | — | Command to execute (for `'exec'` type providers) |
| `options` | `Record<string, unknown>` | — | Additional provider-specific options |

### Package Rules

Package rules in the policy control what happens when a provider reports a finding. The `agentDefault()` preset includes sensible defaults:

- **Block**: critical vulnerabilities, malware, typosquats, AGPL/SSPL licenses
- **Warn**: medium vulnerabilities
- **Approve** (human-in-the-loop): packages less than 30 days old

Customize via the policy:

```typescript
import { agentDefault, merge } from '@agentsh/secure-sandbox/policies';

const policy = merge(agentDefault(), {
  packageRules: [
    { match: { packages: ['lodash'] }, action: 'allow', reason: 'Trusted package' },
    { match: { findingType: 'vulnerability', severity: 'low' }, action: 'allow' },
  ],
});

const sandbox = await secureSandbox(vercel(raw), { policy, packageChecks: {} });
```

### Package Match Fields

| Field | Type | Description |
|-------|------|-------------|
| `packages` | `string[]` | Exact package names to match |
| `namePatterns` | `string[]` | Glob/regex patterns for package names |
| `findingType` | `string` | Finding type (`'vulnerability'`, `'malware'`, `'license'`, `'reputation'`) |
| `severity` | `string \| string[]` | Severity level(s) to match |
| `reasons` | `string[]` | Reasons to match (e.g. `['typosquat']`) |
| `licenseSpdx` | `{ allow?: string[]; deny?: string[] }` | SPDX license criteria |
| `ecosystem` | `string` | Package ecosystem (e.g. `'npm'`, `'pip'`) |
| `options` | `Record<string, unknown>` | Additional match options |

## Secret Providers

Define external secret backends in the policy so HTTP services can reference secrets by name. Secrets are fetched at runtime by the agentsh server — the agent never sees raw credentials.

```typescript
import { agentDefault, merge } from '@agentsh/secure-sandbox/policies';

const policy = merge(agentDefault(), {
  providers: {
    'my-api-key': { type: 'keyring' },
    'vault-secret': {
      type: 'vault',
      address: 'https://vault.example.com',
      namespace: 'prod',
      auth: { method: 'approle', roleId: 'my-role', secretId: 'my-secret' },
    },
    'aws-secret': { type: 'aws-sm', region: 'us-east-1' },
    'gcp-secret': { type: 'gcp-sm', projectId: 'my-project' },
    'azure-secret': { type: 'azure-kv', vaultUrl: 'https://my-vault.vault.azure.net' },
    'op-secret': { type: 'op', serverUrl: 'https://my.1password.com' },
  },
});
```

### Provider Types

| Type | Required Fields | Description |
|------|----------------|-------------|
| `keyring` | — | OS keyring (no config needed) |
| `vault` | `address` | HashiCorp Vault with optional `namespace` and `auth` |
| `aws-sm` | `region` | AWS Secrets Manager |
| `gcp-sm` | `projectId` | Google Cloud Secret Manager |
| `azure-kv` | `vaultUrl` | Azure Key Vault |
| `op` | `serverUrl` | 1Password Connect with optional `apiKey` / `apiKeyRef` |

### Vault Authentication

The `vault` provider supports three auth methods via the `auth` object:

| Method | Fields |
|--------|--------|
| `token` | `token` or `tokenRef` (reference to a secret containing the token) |
| `approle` | `roleId` / `roleIdRef`, `secretId` / `secretIdRef` |
| `kubernetes` | `kubeRole`, `kubeMountPath`, `kubeTokenPath` |

## HTTP Services

Expose external HTTP APIs to the agent through the agentsh proxy with automatic credential injection. The agent calls a local URL; agentsh injects credentials from a secret provider and proxies to the upstream — the agent never sees the raw API key.

```typescript
import { agentDefault, merge } from '@agentsh/secure-sandbox/policies';

const policy = merge(agentDefault(), {
  providers: {
    'github-token': { type: 'keyring' },
  },
  httpServices: [
    {
      name: 'github',
      upstream: 'https://api.github.com',
      exposeAs: 'github.local',
      default: 'deny',
      secret: { ref: 'github-token', format: 'bearer' },
      inject: {
        header: { name: 'Authorization', template: '{{secret}}' },
      },
      rules: [
        { name: 'repos', paths: ['/repos/**'], decision: 'allow' },
        { name: 'user', paths: ['/user'], decision: 'allow' },
      ],
      scrubResponse: true,
    },
  ],
});
```

The agent sees `github.local` and can `curl http://github.local/repos/org/repo` — agentsh resolves it to `api.github.com`, injects the `Authorization: Bearer <token>` header, and proxies the request.

### HTTP Service Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | `string` | Yes | Service identifier |
| `upstream` | `string` | Yes | Upstream URL to proxy to |
| `exposeAs` | `string` | No | Local hostname the agent uses to reach this service |
| `aliases` | `string[]` | No | Additional local hostnames |
| `allowDirect` | `boolean` | No | Allow direct access to upstream (bypass proxy) |
| `default` | `'allow' \| 'deny'` | No | Default decision for unmatched paths |
| `rules` | `HttpServiceRule[]` | No | Path-based access rules |
| `secret` | `{ ref, format }` | No | Secret provider reference for credential injection |
| `inject` | `{ header: { name, template } }` | No | How to inject the secret into requests |
| `scrubResponse` | `boolean` | No | Strip injected credentials from responses |

### HTTP Service Rules

Each rule controls access to specific paths:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | `string` | Yes | Rule identifier |
| `paths` | `string[]` | Yes | Glob patterns for matching request paths |
| `methods` | `string[]` | No | HTTP methods to match (default: all) |
| `decision` | `'allow' \| 'deny' \| 'approve' \| 'audit'` | Yes | What to do when matched |
| `message` | `string` | No | Message shown when rule triggers |
| `timeout` | `string` | No | Request timeout (e.g. `'30s'`) |

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
- `requireWhere` — when `true`, the rule applies only to mutations that have a `WHERE` clause. Useful for catching unguarded `UPDATE`/`DELETE` statements. Only valid when `operations` contains only `modify` and/or `delete` groups (and their aliases).

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
- `databaseRules[].requireWhere: true` rejected when `operations` includes any non-modify/delete group (e.g., `'read'`, `'schema_destroy'`).

The TS schema does **not** validate cross-rule or runtime-dependent constraints — those are deferred to agentsh's startup validator and surface as `ProvisioningError` when `secureSandbox()` is called. These include:

- `tlsMode: 'terminate_plaintext_upstream'` requires loopback/private upstream OR `trustedNetwork: true`.
- Catalog selectors (`relations`/`functions` with `matchObjectResolution: 'catalog_resolved'`) require a terminate-mode Postgres service.
- The "unsafe allow rule" check (`decision: 'allow'` + `operations: ['*']` without a service/family filter).
- Operation alias expansion correctness.
- Approval `timeout` ≤ 600s.

## Audit Integrity

HMAC-chain audit log integrity (v0.18.0+). Each audit record includes a cryptographic hash linking it to the previous record, creating a tamper-evident chain. If any record is modified or deleted, the chain breaks.

```typescript
const sandbox = await secureSandbox(adapter, {
  serverConfig: {
    audit: {
      enabled: true,
      sqlitePath: '/var/lib/agentsh/audit.db',
      integrity: {
        enabled: true,
        algorithm: 'hmac-sha256',
        keySource: 'file',
        keyFile: '/etc/agentsh/hmac.key',
      },
    },
  },
});
```

### Key Sources

| Source | Required Fields | Description |
|--------|----------------|-------------|
| `file` | `keyFile` | Read HMAC key from a local file |
| `env` | `keyEnv` | Read HMAC key from an environment variable |
| `aws_kms` | `awsKms: { keyId, region }` | AWS KMS envelope encryption (optional `encryptedDekFile`) |
| `azure_keyvault` | `azureKeyVault: { vaultUrl, keyName }` | Azure Key Vault (optional `keyVersion`) |
| `hashicorp_vault` | `hashicorpVault: { address, secretPath }` | HashiCorp Vault (optional `authMethod`, `tokenFile`, `kubernetesRole`, `approleId`, `secretId`, `keyField`) |
| `gcp_kms` | `gcpKms: { keyName }` | Google Cloud KMS (optional `encryptedDekFile`) |

## Sprites Adapter

The Sprites adapter wraps a `@fly/sprites` `Sprite` instance for use with Firecracker microVMs on [Sprites.dev](https://sprites.dev).

```typescript
import { secureSandbox } from '@agentsh/secure-sandbox';
import { sprites, spritesDefaults } from '@agentsh/secure-sandbox/adapters/sprites';
import { SpritesClient } from '@fly/sprites';

const client = new SpritesClient(process.env.SPRITES_TOKEN);
const sprite = client.sprite('my-sprite');
const sandbox = await secureSandbox(sprites(sprite), {
  ...spritesDefaults(),
  // your overrides
});

const result = await sandbox.exec('echo hello');
await sandbox.stop(); // calls sprite.delete()
```

### `sprites(sprite)`

Creates a `SandboxAdapter` from a Sprites `Sprite` instance. Uses `sprite.execFile('sh', ['-c', cmd])` internally because the SDK's `sprite.exec()` does a naive whitespace split without shell parsing. File operations use base64 encode/decode piped through `sh`.

### `spritesDefaults()`

Returns Sprites-optimized `Partial<SecureConfig>` with sensible defaults for Firecracker microVMs:

- `installStrategy: 'preinstalled'` — binary baked into the VM image
- `realPaths: true` — use real host paths
- Extended server config: gRPC, audit logging, resource limits, cgroups, DLP, metrics, health checks

Spread into your config and override as needed:

```typescript
const sandbox = await secureSandbox(sprites(sprite), {
  ...spritesDefaults(),
  policy: myPolicy,
  watchtower: 'https://watchtower.example.com',
});
```

### Extended Server Config

The `serverConfig` field on `SecureConfig` accepts additional server configuration sections that are merged into the generated `config.yml`. These are primarily useful for Sprites, Modal, and other advanced deployments:

| Section | Description |
|---------|-------------|
| `grpc` | gRPC server endpoint |
| `serverTimeouts` | HTTP read/write timeouts and max request size |
| `logging` | Log level, format, and output |
| `sessions` | Session base dir, limits, timeouts, cleanup |
| `audit` | SQLite audit logging with optional HMAC integrity chain |
| `sandboxLimits` | Memory, CPU, process, disk I/O (`maxDiskIoMbps`), and network bandwidth (`maxNetworkMbps`) limits |
| `allowDegraded` | Start sandbox even if FUSE/seccomp fail (useful for gVisor) |
| `fuse` | FUSE enable flag, deferred mode, marker file, enable command, `mountBaseDir`, and `audit.*` (see [FUSE Config](#fuse-config)) |
| `networkIntercept` | Network intercept mode, proxy/DNS ports, TLS inspection, transparent proxy, eBPF, and rate limits (see [Network Intercept Config](#network-intercept-config)) |
| `seccompDetails` | Mode, unix socket, execve filtering, syscalls, file monitor, socket family blocking, socketRules, and mitigation sets (see [Seccomp Details Config](#seccomp-details-config)) |
| `cgroups` | Cgroup isolation (`enabled`, `basePath`) |
| `unixSockets` | Unix socket support (`enabled`, `wrapperBin`) |
| `ptrace` | Ptrace-based syscall interception (see [Ptrace Config](#ptrace-config)) |
| `envInject` | Environment variables to inject into sandbox processes |
| `proxy` | MITM proxy mode, port, and provider URLs |
| `dlp` | Data loss prevention (redact mode, patterns) |
| `policiesOverride` | Override default policies directory |
| `approvals` | Human-in-the-loop approval settings |
| `metrics` | Prometheus metrics endpoint |
| `health` | Health and readiness check paths |
| `development` | Development mode flags |

### Seccomp Details Config

The `seccompDetails` section configures seccomp-bpf interception. Setting any subfield implicitly enables `sandbox.seccomp.enabled` (unless `ptrace.enabled` is true, in which case seccomp stays disabled and ptrace handles equivalent enforcement).

```typescript
serverConfig: {
  seccompDetails: {
    mode: 'enforce',                       // 'enforce' | 'audit' | 'disabled'
    unixSocket: {
      enabled: true,                       // Enable unix socket interception
      action: 'enforce',                   // 'enforce' | 'audit'
    },
    execve: true,                          // Intercept execve/execveat for command policy
    execveDetails: {
      maxArgc: 256,                        // Max argument count before truncation
      maxArgvBytes: 16384,                 // Max total argv bytes before truncation
      onTruncated: 'deny',                 // 'deny' | 'allow' | 'approval'
      approvalTimeout: '10s',              // Timeout when onTruncated is 'approval'
      approvalTimeoutAction: 'deny',       // Action on timeout: 'deny' | 'allow'
      internalBypass: ['/usr/bin/agentsh'], // Paths exempt from execve policy
    },
    fileMonitor: {
      enabled: true,
      enforceWithoutFuse: false,           // Enforce file policy via seccomp even without FUSE
      interceptMetadata: false,            // Intercept stat/access/etc.
      openatEmulation: false,              // Rewrite openat for redirect rules
      blockIoUring: false,                 // Block io_uring (bypass channel for file syscalls)
    },
    syscalls: {
      defaultAction: 'allow',             // 'allow' | 'block'
      block: ['ptrace', 'perf_event_open'], // Syscall names to block
      allow: [],                           // Syscall names to always allow
      onBlock: 'errno',                    // 'errno' | 'kill' | 'log' | 'log_and_kill'
    },
    blockedSocketFamilies: [               // Per-AF_* family blocking on socket(2)/socketpair(2)
      { family: 'AF_VSOCK', action: 'log_and_kill' },
      { family: 'AF_ALG' },                // action defaults to 'errno' (returns EAFNOSUPPORT)
    ],
    socketRules: [                         // Fine-grained socket rules (family + type + protocol)
      { name: 'block-netlink-xfrm', family: 'AF_NETLINK', protocol: 'NETLINK_XFRM', action: 'log_and_kill' },
    ],
    mitigationSets: ['dirtyfrag-conservative'], // Named built-in mitigation bundles
    mitigationDirs: ['/etc/agentsh/mitigations'], // Directories with custom mitigation YAML files
  },
}
```

**Top-level `seccompDetails` fields:**

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `mode` | `'enforce' \| 'audit' \| 'disabled'` | `'enforce'` | Overall seccomp enforcement mode |
| `unixSocket` | `object` | — | Unix socket interception config (see below) |
| `execve` | `boolean` | `false` | Intercept execve/execveat for command policy |
| `execveDetails` | `object` | — | Fine-grained execve interception config (auto-sets `execve: true`; see below) |
| `fileMonitor` | `object` | — | File syscall interception config |
| `syscalls` | `object` | — | Custom syscall allow/block list (see below) |
| `blockedSocketFamilies` | `Array<{family, action?}>` | 12 defaults | Per-AF_* family blocking (see below) |
| `socketRules` | `Array<{name, family, type?, protocol?, action?}>` | — | Fine-grained socket rules by family+type+protocol (see below) |
| `mitigationSets` | `string[]` | adapter default | Named built-in mitigation bundles to load (see [Mitigation Sets](#mitigation-sets)) |
| `mitigationDirs` | `string[]` | — | Directories containing custom mitigation YAML files (must be absolute paths) |

**`unixSocket` fields:**

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | `boolean` | — | Enable unix socket path interception |
| `action` | `'enforce' \| 'audit'` | — | Whether to enforce or only audit unix socket access |

**`execveDetails` fields:**

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `maxArgc` | `number` | — | Maximum argument count before truncation |
| `maxArgvBytes` | `number` | — | Maximum total argv size in bytes before truncation |
| `onTruncated` | `'deny' \| 'allow' \| 'approval'` | — | Action when argv is truncated |
| `approvalTimeout` | `string` | — | Timeout for human-approval step (e.g. `'10s'`) |
| `approvalTimeoutAction` | `'deny' \| 'allow'` | — | Action on approval timeout |
| `internalBypass` | `string[]` | — | Executable paths exempt from execve policy |

**`syscalls` fields:**

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `defaultAction` | `'allow' \| 'block'` | — | Baseline action for unlisted syscalls. `'allow'` requires a non-empty `block` list. |
| `block` | `string[]` | — | Syscall names to block |
| `allow` | `string[]` | — | Syscall names to always allow |
| `onBlock` | `'errno' \| 'kill' \| 'log' \| 'log_and_kill'` | `'errno'` | Action when a blocked syscall is intercepted |

**`socketRules` fields** (agentsh v0.19.3+):

Each entry in `socketRules` matches a `socket()` call on all three dimensions simultaneously. Fields are ANDed — unset fields match any value.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | `string` | Yes | Unique rule name (duplicate names are rejected at config-load time) |
| `family` | `string` | Yes | Socket address family (e.g. `'AF_NETLINK'`, `'AF_INET'`) |
| `type` | `string` | No | Socket type (e.g. `'SOCK_RAW'`, `'SOCK_STREAM'`) |
| `protocol` | `string` | No | Protocol name (e.g. `'NETLINK_XFRM'`). `NETLINK_*` is only valid with `family: 'AF_NETLINK'`. |
| `action` | `'errno' \| 'kill' \| 'log' \| 'log_and_kill'` | No | Defaults to `'errno'` |

**Socket family blocking** (agentsh v0.19.0+):

When `blockedSocketFamilies` is **omitted**, agentsh applies a recommended-default list of 12 niche AF_* families at `action: errno`: `AF_ALG`, `AF_VSOCK`, `AF_RDS`, `AF_TIPC`, `AF_KCM`, and the legacy `AF_X25`/`AF_AX25`/`AF_NETROM`/`AF_ROSE`/`AF_DECnet`/`AF_APPLETALK`/`AF_IPX`. This mitigates the recurring CVE class where `socket(AF_<niche>, ...)` is the kernel attack entry point (see [copy.fail](https://copy.fail/#mitigation) for the AF_ALG case).

| Caller passes | Behavior |
|---|---|
| field omitted | agentsh applies the 12-family default list at `errno` |
| `blockedSocketFamilies: []` | opts out of all family blocking |
| non-empty list | overrides the defaults with the supplied entries |

| `action` | Effect | Audit event |
|---|---|---|
| `errno` (default) | Returns `EAFNOSUPPORT` (97) to the caller | none |
| `kill` | Process killed by `SCMP_ACT_KILL_PROCESS` | none |
| `log` | Returns `EAFNOSUPPORT` and emits audit event | `seccomp_socket_family_blocked` (outcome: `denied`) |
| `log_and_kill` | Process killed by `SIGKILL` and emits audit event | `seccomp_socket_family_blocked` (outcome: `killed`) |

`family` accepts either a name (`'AF_VSOCK'`) or a numeric string (`'40'`). Names resolve via a built-in table; numbers in `[0, 64)` are accepted as a fallback. Unknown names and out-of-range numbers are rejected at config-load time. When `ptrace.enabled` is true, the ptrace fallback engine handles family blocking and emits identical audit events. See [agentsh seccomp docs](https://github.com/canyonroad/agentsh/blob/main/docs/seccomp.md#socket-family-blocking) for the canonical reference.

### Mitigation Sets

**Mitigation sets**: Named built-in mitigation YAML files that expand into `socketRules` + `blockedSocketFamilies` server-side. agentsh ships `dirtyfrag-conservative` as a built-in (Openwall Dirty Frag advisory, May 2026 — blocks AF_RXRPC and AF_NETLINK+NETLINK_XFRM with `log_and_kill`). The `sprites`, `freestyle`, `runloop`, and `exe` adapter defaults enable this mitigation by default. To opt out: `mitigationSets: []`. To use the typed constant: `mitigationSets: [KNOWN_MITIGATIONS.dirtyfragConservative]`.

| Mitigation set | Description |
|---------------|-------------|
| `dirtyfrag-conservative` | Openwall Dirty Frag (May 2026): blocks `AF_RXRPC` and `AF_NETLINK+NETLINK_XFRM` with `log_and_kill` |

Custom mitigation YAML files can be loaded from directories listed in `mitigationDirs` (must be absolute paths).

### Network Intercept Config

The `networkIntercept` section controls the agentsh network proxy and eBPF enforcement layer.

```typescript
serverConfig: {
  networkIntercept: {
    enabled: true,                         // Enable network interception
    proxyPort: 18081,                      // Proxy listen port
    dnsPort: 18053,                        // DNS proxy listen port
    tlsInspection: {
      enabled: true,                       // Enable TLS MITM inspection
      caCert: '/etc/agentsh/ca.crt',       // Path to CA certificate PEM
      caKey: '/etc/agentsh/ca.key',        // Path to CA private key PEM
    },
    transparent: {
      enabled: true,                       // Enable transparent proxy mode
      subnetBase: '10.99.0.0/16',          // Subnet for transparent proxy routing
    },
    ebpf: {
      enabled: true,                       // Enable eBPF enforcement
      required: false,                     // Fail if eBPF unavailable
      enforce: true,                       // Enforce policy via eBPF
      resolveRdns: true,                   // Reverse-DNS resolution in eBPF map
      enforceWithoutDns: false,            // Enforce even when DNS proxy is bypassed
      mapAllowEntries: 4096,               // eBPF allow-map capacity
      mapDenyEntries: 4096,                // eBPF deny-map capacity
      mapLpmEntries: 1024,                 // eBPF LPM (CIDR) allow-map capacity
      mapLpmDenyEntries: 1024,             // eBPF LPM deny-map capacity
      mapDefaultEntries: 256,              // eBPF default-action map capacity
      dnsRefreshSeconds: 30,               // How often to refresh DNS-resolved IPs in eBPF maps
      dnsMaxTtlSeconds: 300,               // Cap on DNS TTLs used for eBPF map entries
    },
    rateLimits: {
      enabled: true,                       // Enable rate limiting
      globalRpm: 6000,                     // Global requests-per-minute limit
      globalBurst: 200,                    // Global burst allowance
      perDomain: [                         // Per-domain overrides
        { domain: 'api.example.com', rpm: 600, burst: 20 },
      ],
    },
  },
}
```

**Top-level `networkIntercept` fields:**

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | `boolean` | — | Enable network interception |
| `proxyPort` | `number` | — | TCP port the proxy listens on |
| `dnsPort` | `number` | — | UDP port the DNS proxy listens on |
| `interceptMode` | `string` | — | Low-level intercept mode hint |
| `proxyListenAddr` | `string` | — | Listen address for the proxy |
| `tlsInspection` | `object` | — | TLS inspection config (see below) |
| `transparent` | `object` | — | Transparent proxy config (see below) |
| `ebpf` | `object` | — | eBPF enforcement config (see below) |
| `rateLimits` | `object` | — | Rate limiting config (see below) |

**`tlsInspection` fields:**

| Field | Type | Description |
|-------|------|-------------|
| `enabled` | `boolean` | Enable TLS MITM inspection (requires `caCert`/`caKey`) |
| `caCert` | `string` | Path to the CA certificate PEM file |
| `caKey` | `string` | Path to the CA private key PEM file |

**`transparent` fields:**

| Field | Type | Description |
|-------|------|-------------|
| `enabled` | `boolean` | Enable transparent proxy mode |
| `subnetBase` | `string` | CIDR subnet for transparent routing (e.g. `'10.99.0.0/16'`) |

**`ebpf` fields:**

| Field | Type | Description |
|-------|------|-------------|
| `enabled` | `boolean` | Enable the eBPF network enforcement layer |
| `required` | `boolean` | Fail provisioning if eBPF is unavailable |
| `enforce` | `boolean` | Enforce policy decisions via eBPF (vs. audit-only) |
| `resolveRdns` | `boolean` | Reverse-DNS resolution for IP → domain mapping in eBPF maps |
| `enforceWithoutDns` | `boolean` | Enforce even when the DNS proxy is bypassed |
| `mapAllowEntries` | `number` | Capacity of the eBPF allow map |
| `mapDenyEntries` | `number` | Capacity of the eBPF deny map |
| `mapLpmEntries` | `number` | Capacity of the eBPF LPM (CIDR) allow map |
| `mapLpmDenyEntries` | `number` | Capacity of the eBPF LPM deny map |
| `mapDefaultEntries` | `number` | Capacity of the eBPF default-action map |
| `dnsRefreshSeconds` | `number` | Interval for refreshing DNS-resolved IPs in eBPF maps |
| `dnsMaxTtlSeconds` | `number` | Maximum TTL cap applied to DNS entries in eBPF maps |

**`rateLimits` fields:**

| Field | Type | Description |
|-------|------|-------------|
| `enabled` | `boolean` | Enable rate limiting |
| `globalRpm` | `number` | Global requests-per-minute ceiling across all domains |
| `globalBurst` | `number` | Global burst allowance (token bucket) |
| `perDomain` | `Array<{domain, rpm?, burst?}>` | Per-domain RPM and burst overrides |

### FUSE Config

The `fuse` section controls FUSE-based filesystem virtualization.

```typescript
serverConfig: {
  fuse: {
    enabled: true,                         // Enable FUSE filesystem
    deferred: true,                        // Defer FUSE mount until first session
    deferredMarkerFile: '/tmp/.agentsh-fuse-enabled',
    deferredEnableCommand: ['sudo', '/bin/chmod', '666', '/dev/fuse'],
    mountBaseDir: '/mnt/agentsh',          // Base directory for FUSE mounts
    audit: {
      enabled: true,                       // Enable FUSE-level audit
      mode: 'soft_delete',                 // 'monitor' | 'soft_block' | 'soft_delete' | 'strict'
      trashPath: '/var/lib/agentsh/trash', // Where soft-deleted files go
      ttl: '24h',                          // Soft-delete retention duration
      quota: '5GiB',                       // Max trash directory size
      strictOnAuditFailure: false,         // Block operation if audit write fails
      maxEventQueue: 8192,                 // In-memory audit event queue depth
      hashSmallFilesUnder: '1MiB',         // Hash files below this size for audit records
    },
  },
}
```

**`fuse` fields:**

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | `boolean` | `false` | Enable FUSE filesystem |
| `deferred` | `boolean` | — | Defer FUSE mount to first session start |
| `deferredMarkerFile` | `string` | — | Path to marker file indicating FUSE is ready |
| `deferredEnableCommand` | `string[]` | — | Command to run to enable FUSE (e.g. `chmod 666 /dev/fuse`) |
| `mountBaseDir` | `string` | — | Override the base directory for FUSE workspace mounts |
| `audit` | `object` | — | FUSE-level audit config (see below) |

**`fuse.audit` fields:**

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | `boolean` | — | Enable FUSE audit logging |
| `mode` | `'monitor' \| 'soft_block' \| 'soft_delete' \| 'strict'` | — | Audit enforcement mode. `monitor`: log only. `soft_block`: block denied writes. `soft_delete`: redirect deletes to trash. `strict`: block and fail hard on audit errors. |
| `trashPath` | `string` | — | Directory where soft-deleted files are moved |
| `ttl` | `string` | — | Retention duration for soft-deleted files (e.g. `'24h'`) |
| `quota` | `string` | — | Maximum trash directory size (e.g. `'5GiB'`) |
| `strictOnAuditFailure` | `boolean` | — | Block the file operation if writing the audit record fails |
| `maxEventQueue` | `number` | — | Depth of the in-memory audit event queue |
| `hashSmallFilesUnder` | `string` | — | Hash file contents for audit records when file is below this size (e.g. `'1MiB'`) |

### Ptrace Config

The `ptrace` section enables ptrace-based syscall interception, used on gVisor platforms where seccomp user-notify is unavailable. Ptrace is mutually exclusive with seccomp execve filtering and unix socket interception.

```typescript
serverConfig: {
  ptrace: {
    enabled: true,                    // Master switch (default: false)
    attachMode: 'children',           // 'children' (PTRACE_SEIZE on children) or 'pid' (attach to specific PID)
    maskTracerPid: 'off',             // Hide tracer PID from /proc/*/status
    trace: {
      execve: true,                   // Intercept command execution (execve/execveat)
      file: true,                     // Intercept file operations (openat, unlinkat, renameat2, etc.)
      network: true,                  // Intercept network calls (connect, bind) + DNS proxy
      signal: true,                   // Intercept signals (kill, tgkill, tkill)
    },
    performance: {
      seccompPrefilter: false,        // BPF pre-filter for performance (disable on gVisor)
      maxTracees: 500,                // Maximum concurrent traced threads
      maxHoldMs: 5000,                // Maximum time to hold a syscall (ms)
    },
    onAttachFailure: 'fail_open',     // 'fail_open' (continue) or 'fail_closed' (abort)
  },
}
```

## Modal Adapter

The Modal adapter wraps a Modal sandbox for use with gVisor-based sandboxes on [Modal](https://modal.com). Since gVisor doesn't support seccomp user-notify or Landlock, the adapter uses ptrace-based enforcement.

```typescript
import { secureSandbox } from '@agentsh/secure-sandbox';
import { modal, modalDefaults } from '@agentsh/secure-sandbox/adapters/modal';

const sandbox = await secureSandbox(modal(modalSandbox), {
  ...modalDefaults(),
  // your overrides
});

const result = await sandbox.exec('echo hello');
await sandbox.stop(); // calls sandbox.terminate()
```

### `modal(sandbox)`

Creates a `SandboxAdapter` from a Modal sandbox object. The sandbox must implement `exec(...args)` returning a process with `wait()`, `stdout.read()`, `stderr.read()`, and `returncode`. File operations use base64 encode/decode piped through `sh`. Modal containers run as root so the `sudo` flag is dropped.

### `modalDefaults()`

Returns Modal-optimized `Partial<SecureConfig>` with sensible defaults for gVisor/ptrace environments:

- `installStrategy: 'download'` — download agentsh binary from GitHub releases
- `realPaths: true` — use real host paths
- **ptrace enabled** with all trace subsystems (execve, file, network, signal)
- `seccompPrefilter: false` — gVisor blocks BPF injection
- `allowDegraded: true` — graceful fallback for FUSE/seccomp
- FUSE deferred with marker file
- unix sockets and cgroups disabled (Modal handles resource limits)
- DLP, audit logging, metrics, and health checks enabled

Spread into your config and override as needed:

```typescript
const sandbox = await secureSandbox(modal(modalSandbox), {
  ...modalDefaults(),
  policy: myPolicy,
  watchtower: 'https://watchtower.example.com',
});
```

## Runloop Adapter

The Runloop adapter wraps a [Runloop](https://runloop.ai) devbox for use with persistent cloud development environments.

```typescript
import { secureSandbox } from '@agentsh/secure-sandbox';
import { runloop, runloopDefaults } from '@agentsh/secure-sandbox/adapters/runloop';
import RunloopSdk from '@runloop/api-client';

const client = new RunloopSdk();
const devbox = await client.devboxes.createAndAwaitRunning({});
const sandbox = await secureSandbox(runloop({ client, id: devbox.id }), {
  ...runloopDefaults(),
});

const result = await sandbox.exec('echo hello');
await sandbox.stop(); // shuts down the devbox
```

### `runloop({ client, id })`

Creates a `SandboxAdapter` from a Runloop SDK client and devbox ID. Commands are executed via `client.devboxes.executeSync()`. File operations use base64 encode/decode.

### `runloopDefaults()`

Returns Runloop-optimized `Partial<SecureConfig>` with a standalone high-security `PolicyDefinition`:

- `installStrategy: 'download'` — download agentsh from GitHub releases
- `realPaths: true` — use real host paths
- Deny-by-default file, network, and command rules
- Full server config: gRPC, audit logging, FUSE deferred, cgroups, DLP, ptrace (execve only)

## exe.dev Adapter

The exe.dev adapter wraps a persistent [exe.dev](https://exe.dev) VM accessed via SSH through the exe.dev gateway. exe.dev VMs have full kernel capabilities, enabling all enforcement layers.

```typescript
import { secureSandbox } from '@agentsh/secure-sandbox';
import { exe, exeDefaults } from '@agentsh/secure-sandbox/adapters/exe';

// VM already created: ssh exe.dev new --name=my-vm --image=ubuntu:22.04
const sandbox = await secureSandbox(exe('my-vm'), {
  ...exeDefaults(),
});

const result = await sandbox.exec('echo hello');
// stop() is a no-op — exe.dev VMs are persistent
// Destroy externally: ssh exe.dev rm my-vm
await sandbox.stop();
```

### `exe(vmName: string)`

Creates a `SandboxAdapter` from an exe.dev VM name. The VM must already exist (created via `ssh exe.dev new`). All commands route through the exe.dev SSH gateway: `ssh exe.dev ssh <vmName> <command>`.

Uses `child_process.execFile` (no local shell) with single-quote escaping for the gateway shell layer. Default timeout: 120s, max buffer: 50MB.

- `exec()` — shell-escapes commands, supports `sudo`, `cwd`, `env`, and `detached` options
- `writeFile()` — base64-encodes content and pipes through SSH
- `readFile()` — `cat` via SSH
- `stop()` — no-op (exe.dev VMs are persistent; destroy externally via `ssh exe.dev rm <vmName>`)
- `fileExists()` — `test -f` via SSH (enables skipping agentsh download when already installed)

### `exeDefaults()`

Returns exe.dev-optimized `Partial<SecureConfig>` with full enforcement and a standalone high-security `PolicyDefinition`:

- `installStrategy: 'download'` — skips download automatically if agentsh is already installed
- `allowDegraded: false` — exe.dev has full kernel capabilities; do not degrade
- **All enforcement layers**: ptrace + seccomp + Landlock + FUSE + cgroups
- Deny-by-default file rules with explicit workspace allows (`/root`, `/workspace`)
- Network: localhost + package registries only (no LLM providers, no GitHub)
- Blocks exe.dev internals: `shelley`, `iptables`, `systemctl`
- DLP with custom patterns for OpenAI, Anthropic, AWS, GitHub, JWT, Slack tokens
- Conservative resource limits: 2GB RAM, 50% CPU, 100 PIDs
- Full audit logging (all operations logged)

Spread into your config and override as needed:

```typescript
const sandbox = await secureSandbox(exe('my-vm'), {
  ...exeDefaults(),
  policy: myPolicy,
});
```

## Freestyle Adapter

The Freestyle adapter wraps a [Freestyle](https://freestyle.sh) Firecracker-backed Linux VM created via the `freestyle-sandboxes` SDK. Freestyle exposes a typed filesystem API and a declarative `VmSpec` builder, which lets you bake agentsh into the VM image at snapshot time and skip the cold-start install entirely.

```typescript
import { secureSandbox } from '@agentsh/secure-sandbox';
import {
  freestyle,
  freestyleDefaults,
  configureFreestyleSpec,
} from '@agentsh/secure-sandbox/adapters/freestyle';
import { freestyle as freestyleClient, VmSpec } from 'freestyle-sandboxes';

const fs = freestyleClient({ apiKey: process.env.FREESTYLE_API_KEY });

// Bake agentsh into a snapshot — fastest cold boots
const { vm } = await fs.vms.create({
  spec: configureFreestyleSpec(new VmSpec().snapshot()),
});

const sandbox = await secureSandbox(freestyle(vm), {
  ...freestyleDefaults(),
  installStrategy: 'preinstalled',
});

const result = await sandbox.exec('echo hello');
await sandbox.stop(); // calls vm.stop()
```

### `freestyle(vm)`

Creates a `SandboxAdapter` from a Freestyle VM instance. Unlike shell-only adapters, Freestyle's typed `vm.fs.*` API is used directly for file I/O — no base64-over-exec workaround.

The adapter expects these methods on `vm`:

- `vm.exec({ command, timeoutMs? }) → Promise<{ stdout?, stderr?, statusCode? }>`
- `vm.fs.writeTextFile(path, content)` / `vm.fs.writeFile(path, Buffer)` — string vs binary
- `vm.fs.readTextFile(path)`
- `vm.fs.exists(path)`
- `vm.stop()`

`exec()` wraps every command in `sh -c` so `cwd`, `env`, `sudo`, and shell metacharacters work consistently. `detached` commands are wrapped in `nohup sh -c ... &` so they survive the parent shell exit. `fileExists()` lets the provisioner skip the agentsh download when the binary is already baked into the snapshot.

### `freestyleDefaults()`

Returns Freestyle-optimized `Partial<SecureConfig>` with a standalone `PolicyDefinition` ported from the production `agentsh-freestyle/default.yaml`:

- `installStrategy: 'download'` — defaults to runtime install; set `'preinstalled'` when using `configureFreestyleSpec`
- `realPaths: true`
- `workspace: '/home/user'` — matches Freestyle VM home
- **`allowDegraded: true`** — Freestyle kernels lack Yama, so seccomp `fileMonitor` is disabled and the sandbox settles into `minimal` security mode (per-command seccomp wrapper + network proxy + FUSE soft-delete + cgroups)
- **FUSE deferred** — enabled at first session start via `sudo /bin/chmod 666 /dev/fuse`, guarded by `/tmp/.agentsh-fuse-enabled`
- **seccomp `fileMonitor: false`** — conflicts with FUSE on Yama-less kernels
- DLP with custom patterns for OpenAI, Anthropic, AWS, GitHub, JWT, Slack tokens
- Two-tier resource caps: outer server bound at 4 GB / 100% CPU / 256 procs, inner per-policy `resourceLimits` at 2 GB / 50% CPU / 100 PIDs
- Workspace allows `/home/user/**` and `/workspace/**`; denies `/etc/systemd/**`, `/run/systemd/**`, `/usr/bin/envd`, `/usr/bin/socat`, and other Freestyle infrastructure
- Network: localhost + npm/PyPI/crates/Go module registries only; blocks cloud metadata IPs and the Freestyle internal events service

> **Note on `commands`:** the reference YAML uses `args_patterns` to gate `npm install`, `pip install`, etc. behind an approval step. The TS `CommandRuleSchema` is a `{allow}/{deny}/{redirect}` union with no `args_patterns` field, so dev tools stay allowed at the command layer. The real enforcement for untrusted installs is the network allowlist (only registries are reachable). Consumers who need per-subcommand approval should bypass `freestyleDefaults()` and load the raw YAML via agentsh's own policy loader.

### `configureFreestyleSpec(spec, opts?)`

Bakes agentsh into a Freestyle `VmSpec` by adding apt deps, install/startup scripts, and two systemd units: a oneshot installer and the agentsh server. Call this on a fresh `VmSpec` (typically `new VmSpec().snapshot()`) before passing it to `fs.vms.create`.

```typescript
const spec = configureFreestyleSpec(new VmSpec().snapshot(), {
  agentshVersion: '0.19.3',          // optional, defaults to library-pinned version
  policyYaml: customPolicyYaml,      // optional, defaults to freestyleDefaults() policy
  configYaml: customServerConfigYaml, // optional, defaults to freestyleDefaults() server config
});
```

The `agentsh` systemd service is wired with `Requires=install-agentsh.service` (hard dependency) so the server never starts if installation failed.

`agentshVersion` is validated against `^\d+\.\d+\.\d+(?:-[a-zA-Z0-9.-]+)?$` before being substituted into the install script — invalid values throw rather than risking shell injection.

After the snapshot boots, agentsh is already running and the shell shim is installed, so pair this with `installStrategy: 'preinstalled'` to skip the runtime install path entirely.

## Custom Adapter

Any sandbox that can run commands works with `secureSandbox()`. Implement the `SandboxAdapter` interface:

```typescript
import { secureSandbox } from '@agentsh/secure-sandbox';
import type { SandboxAdapter } from '@agentsh/secure-sandbox';

const myAdapter: SandboxAdapter = {
  async exec(cmd, args, opts) {
    // Your sandbox's exec implementation
    return { stdout: '', stderr: '', exitCode: 0 };
  },
  async writeFile(path, content) { /* ... */ },
  async readFile(path) { /* ... */ },
};

const sandbox = await secureSandbox(myAdapter);
```

The adapter must implement three methods:

| Method | Signature | Description |
|--------|-----------|-------------|
| `exec` | `(cmd: string, args: string[], opts?: ExecOpts) => Promise<ExecResult>` | Execute a command in the sandbox |
| `writeFile` | `(path: string, content: string) => Promise<void>` | Write a file to the sandbox filesystem |
| `readFile` | `(path: string) => Promise<string>` | Read a file from the sandbox filesystem |

## Testing

Mock utilities for unit testing without a real sandbox:

```typescript
import { mockSecuredSandbox } from '@agentsh/secure-sandbox/testing';

const sandbox = mockSecuredSandbox({
  execResults: [{ stdout: 'hello\n', stderr: '', exitCode: 0 }],
  securityMode: 'full',
});

const result = await sandbox.exec('echo hello');
expect(result.stdout).toBe('hello\n');
```

`mockSecuredSandbox` returns a `SecuredSandbox` that replays canned responses without any sandbox or policy engine. Use it in unit tests to verify your agent logic without spinning up real infrastructure.

### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `execResults` | `ExecResult[]` | `[]` | Responses to return from `exec()`, consumed in order |
| `readFileResults` | `string[]` | `[]` | Responses to return from `readFile()` |
| `writeFileResults` | `WriteFileResult[]` | `[]` | Responses to return from `writeFile()` |
| `securityMode` | `SecurityMode` | `'full'` | The `securityMode` property value |
| `sessionId` | `string` | Random UUID | The `sessionId` property value |

### Live E2E Runners

The repository also ships provider-backed end-to-end runners under `src/e2e/`:

```bash
npm run test:e2e
npm run test:e2e:runloop
npm run test:e2e:exe
npm run test:e2e:freestyle
npm run test:e2e:modal
npm run test:e2e:sprites
```

`npm run test:e2e` covers the shared Vitest matrix for Vercel, Cloudflare, Blaxel, E2B, and Daytona. The provider-specific runners load credentials from `.env.e2e`.

- `test:e2e:modal` requires `MODAL_TOKEN_ID` and `MODAL_TOKEN_SECRET`. The runner uses `MODAL_PYTHON` when set, otherwise it auto-detects `.venv-modal/bin/python3` before falling back to `python3`.
- `test:e2e:sprites` requires `SPRITES_TOKEN` or `FLY_API_TOKEN`. If `SPRITES_NAME` is missing or stale, the runner can auto-create and delete a temporary sprite when `FLY_API_TOKEN` and `SPRITES_ORG` are set.

## Constants and Exports

### `KNOWN_MITIGATIONS`

A typed constant object mapping friendly camelCase names to the raw agentsh mitigation set IDs. Use these in `seccompDetails.mitigationSets` instead of raw strings to get autocomplete and a single update point when agentsh ships new built-ins.

```typescript
import { KNOWN_MITIGATIONS } from '@agentsh/secure-sandbox';

await secureSandbox(adapter, {
  seccompDetails: {
    mitigationSets: [KNOWN_MITIGATIONS.dirtyfragConservative],
  },
});
```

| Constant | Raw value | Description |
|----------|-----------|-------------|
| `KNOWN_MITIGATIONS.dirtyfragConservative` | `'dirtyfrag-conservative'` | Openwall Dirty Frag advisory (May 2026): blocks `AF_RXRPC` and `AF_NETLINK+NETLINK_XFRM` with `log_and_kill` |

`KnownMitigation` is exported as a type union of all known raw values (`'dirtyfrag-conservative' | ...`). The `sprites`, `freestyle`, `runloop`, and `exe` adapter defaults include `dirtyfrag-conservative` automatically. To opt out: `mitigationSets: []`.
