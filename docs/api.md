# API Reference

## `secureSandbox(adapter, config?)`

Secures any sandbox via its adapter. Returns a `SecuredSandbox` that mediates every command, file read, and file write through the [agentsh](https://www.agentsh.org) policy engine.

```typescript
import { secureSandbox } from '@agentsh/secure-sandbox';

const sandbox = await secureSandbox(adapter, {
  policy: agentDefault(),              // Policy to enforce (default: agentDefault())
  installStrategy: 'download',         // 'download' | 'upload' | 'preinstalled' | 'running'
  agentshVersion: '0.16.2',            // agentsh binary version
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
| `agentshVersion` | `string` | Latest | Pin a specific agentsh version |
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
| `full` | seccomp + FUSE + Landlock + network proxy | Full Linux with FUSE support (E2B, Daytona, Blaxel) |
| `ptrace` | ptrace syscall interception + network proxy (exec, file, network, signal) | gVisor-based platforms (Modal) |
| `landlock` | Landlock + network proxy (no FUSE) | Firecracker VMs (Vercel, Cloudflare) |
| `landlock-only` | Landlock filesystem restrictions only | Limited kernel support |
| `minimal` | Policy evaluation only, no kernel enforcement | Containers without seccomp |

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
| `audit` | SQLite audit logging |
| `sandboxLimits` | Memory, CPU, and process limits |
| `allowDegraded` | Start sandbox even if FUSE/seccomp fail (useful for gVisor) |
| `fuse` | FUSE deferred mode, marker file, and enable command |
| `networkIntercept` | Network intercept mode and proxy address |
| `seccompDetails` | Execve filtering and file monitor |
| `cgroups` | Cgroup isolation |
| `unixSockets` | Unix socket support |
| `ptrace` | Ptrace-based syscall interception (see [Ptrace Config](#ptrace-config)) |
| `envInject` | Environment variables to inject into sandbox processes |
| `proxy` | MITM proxy mode, port, and provider URLs |
| `dlp` | Data loss prevention (redact mode, patterns) |
| `policiesOverride` | Override default policies directory |
| `approvals` | Human-in-the-loop approval settings |
| `metrics` | Prometheus metrics endpoint |
| `health` | Health and readiness check paths |
| `development` | Development mode flags |

### Ptrace Config

The `ptrace` section enables ptrace-based syscall interception, used on gVisor platforms where seccomp user-notify is unavailable. Ptrace is mutually exclusive with seccomp execve filtering and unix socket interception.

```typescript
serverConfig: {
  ptrace: {
    enabled: true,                    // Master switch (default: false)
    attachMode: 'children',           // 'children' (PTRACE_SEIZE on children) or 'pid' (attach to specific PID)
    maskTracerPid: 'off',             // Hide tracer PID from /proc/*/status ('off' only in v0.16.2)
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
