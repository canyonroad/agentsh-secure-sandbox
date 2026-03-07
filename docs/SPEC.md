# @agentsh/secure-sandbox — Technical Specification

**Version:** 0.1.0-final
**Date:** March 2026
**Status:** Ready for implementation

---

## 1. Overview

`@agentsh/secure-sandbox` is a TypeScript library that installs and configures
[agentsh](https://github.com/canyonroad/agentsh) inside any supported sandbox
provider, giving developers syscall-level policy enforcement with minimal
code changes.

The library is framework-agnostic — it works with Vercel AI SDK, LangChain,
OpenAI Agents SDK, or no AI framework at all. Anywhere you use a sandbox
to run untrusted code, `@agentsh/secure-sandbox` adds execution-layer security.

The library does three things:

1. Normalizes sandbox provider APIs behind a common adapter interface.
2. Provisions agentsh inside the sandbox (install binary, write policy, start
   server, install shell shim) — all before the agentic loop begins.
3. Returns a `SecuredSandbox` whose runtime methods route ALL operations
   through agentsh — never through raw provider APIs.

### 1.1 Security boundary statement

This library governs runtime operations that flow through agentsh. It does
not replace the isolation guarantees of the underlying sandbox provider.
The sandbox provider is responsible for host-level isolation (VM boundary,
network namespace, filesystem mount). agentsh is responsible for
per-operation policy enforcement within that boundary (which files, which
commands, which network destinations, with what verdicts).

### 1.2 Prerequisites

This library requires **agentsh v0.14.0+** with support for:

- **Multi-layer policy evaluation** (`system_dir` config option) for the
  self-protection guarantee (see Section 9.4). If not yet implemented in
  agentsh core, this feature must be added before this library ships v0.1.
- **Security modes** (`full`, `landlock`, `landlock-only`, `minimal`) with
  auto-detection via `agentsh detect`.
- **Enforced redirects** (`enforceRedirects` flag) for blocking execution
  instead of shadowing to stub binary.
- **Path canonicalization** — resolves symlinks before policy evaluation,
  preventing `/proc/self/root` and symlink-based bypass attacks (v0.14.0).
- **Transparent command unwrapping** — peels wrapper commands (`env`, `sudo`,
  `nice`, `nohup`, etc.) to evaluate the real payload against policy (v0.14.0).
- **W3C trace context propagation** — `traceparent` header threading through
  HTTP, gRPC, and events for distributed tracing correlation (v0.12.0).
- **Package install security scanning** — detects install commands across
  npm, pip, uv, pnpm, yarn, poetry with vulnerability/scorecard checks (v0.12.0).

---

## 2. Design Principles

**P1 — Sandbox-agnostic.** The library does not force a specific sandbox
provider. It ships adapters for common providers and accepts custom adapters
for anything else.

**P2 — Optional peer dependencies.** Installing `@agentsh/secure-sandbox`
does not pull in `@vercel/sandbox`, `e2b`, or `@daytonaio/sdk`. The developer
installs only the provider they use. The library declares supported versions
as optional peer dependencies.

**P3 — Policy is code, frozen before execution.** Policy is defined as
TypeScript, validated with Zod at definition time, serialized to YAML,
written as a root-owned read-only file inside the sandbox, and protected
by agentsh's system policy layer. The agent cannot modify it at runtime.

**P4 — Minimal surface.** The public API is two functions (`secureSandbox`,
`createSandbox`), a set of adapters, a set of policy presets, and one
interface (`SecuredSandbox`). That's it.

**P5 — Version-pinned provider support.** Each adapter declares which
versions of the provider SDK it supports. Breaking changes in provider
APIs are handled by adapter version bumps, not by the core library.

**P6 — Provisioning and runtime are separate channels.** The adapter
(raw provider API) is used only during provisioning — installing agentsh,
writing config, starting the server. After provisioning completes, all
runtime operations flow through `agentsh exec` invoked via the adapter's
exec method as a transport. The adapter is never used to execute user
operations directly or to perform file I/O through provider-native APIs.

---

## 3. Package Structure

```
@agentsh/secure-sandbox
├── index.ts                 # Exports: secureSandbox, createSandbox, SecuredSandbox type
├── adapters/
│   ├── index.ts             # Re-exports all adapters
│   ├── vercel.ts            # @vercel/sandbox adapter
│   ├── e2b.ts               # @e2b/code-interpreter adapter
│   ├── daytona.ts           # @daytonaio/sdk adapter
│   ├── docker.ts            # Docker CLI / Dockerode adapter
│   └── ssh.ts               # SSH adapter (via ssh2)
├── policies/
│   ├── index.ts             # Re-exports presets + merge utility
│   ├── presets.ts           # devSafe, ciStrict, agentSandbox
│   ├── schema.ts            # Zod schemas for PolicyDefinition
│   └── serialize.ts         # PolicyDefinition → agentsh YAML
├── core/
│   ├── provision.ts         # Install agentsh, write policy, start server
│   ├── runtime.ts           # SecuredSandbox implementation (exec-mediated)
│   ├── integrity.ts         # SHA256 checksum verification
│   ├── snapshot.ts          # Snapshot caching logic
│   └── types.ts             # SandboxAdapter, SecuredSandbox, etc.
└── package.json
```

---

## 4. Dependency Model

### 4.1 Hard dependencies (installed with the library)

| Package  | Purpose                        |
| -------- | ------------------------------ |
| `zod`    | Policy schema validation       |
| `js-yaml`| PolicyDefinition → YAML        |

### 4.2 Optional peer dependencies (installed by the developer)

Each adapter declares a supported version range. The library does not
import any provider SDK at the top level — adapters use dynamic imports
and fail with a clear error if the peer dependency is missing.

| Adapter    | Peer dependency         | Supported versions     | Notes                                    |
| ---------- | ----------------------- | ---------------------- | ---------------------------------------- |
| `vercel`   | `@vercel/sandbox`       | `^1.0.0`              | Firecracker microVM, Node/Python         |
| `e2b`      | `@e2b/code-interpreter` | `^1.2.0`              | Firecracker microVM, Jupyter             |
| `daytona`  | `@daytonaio/sdk`        | `^0.12.0 \|\| ^1.0.0` | OCI containers, long-lived              |
| `docker`   | `dockerode`             | `^4.0.0`              | Optional; falls back to CLI              |
| `ssh`      | `ssh2`                  | `^1.16.0`             | For pre-isolated Linux hosts (advanced)  |

**Note on SSH:** An SSH-connected Linux host is not a sandbox by itself.
The SSH adapter is for use with already-isolated targets (dedicated VMs,
CI runners, air-gapped machines). It does not provide host-level isolation.
The developer is responsible for ensuring the target is appropriately
isolated before using this adapter.

### 4.3 agentsh binary

The library provisions the agentsh binary inside the sandbox at setup time.
It does not bundle the binary in the npm package.

| Setting               | Default                                                       | Override                      |
| --------------------- | ------------------------------------------------------------- | ----------------------------- |
| Binary source         | `github.com/canyonroad/agentsh/releases/download/{version}/`  | `AGENTSH_BINARY_URL` env var  |
| Version               | Pinned per library release (currently `0.14.0`)               | `agentshVersion` in config    |
| Platform detection    | `uname -m` inside sandbox → `linux_amd64` or `linux_arm64`   | `agentshArch` in config       |
| Checksum verification | SHA256, pinned per version in library source                  | `agentshChecksum` in config   |

### 4.4 Binary integrity verification

Every agentsh binary download is verified against a SHA256 checksum
pinned in the library source code. The verification flow:

1. Library contains a `CHECKSUMS` map: `{ version → { arch → sha256 } }`.
2. After download, compute SHA256 of the downloaded file inside the sandbox.
3. Compare against the pinned checksum.
4. If mismatch, delete the file and throw `IntegrityError`.

Checksums for v0.14.0 (from GitHub release assets):

```
linux_amd64.tar.gz: 2ab8ba0d6637fe1a5badf840c3db197161a6f9865d721ed216029d229b1b9bbc
linux_arm64.tar.gz: 929d18dd9fe36e9b2fa830d7ae64b4fb481853e743ade8674fcfcdc73470ed53
linux_amd64.deb:    65deb2f557dcf4e72c15c324b42a22ec159e04754f773829ce47546562652c7f
linux_arm64.deb:    e3980e3c110d6b5ab42a656ea6705d33d7181c155342ad276bfc09035407ee4a
```

If `AGENTSH_BINARY_URL` is set (custom download location), checksum
verification is still enforced unless explicitly disabled with
`skipIntegrityCheck: true`. The config option is named to make the
tradeoff visible.

### 4.5 package.json (relevant fields)

```json
{
  "name": "@agentsh/secure-sandbox",
  "version": "0.1.0",
  "type": "module",
  "exports": {
    ".": "./dist/index.js",
    "./adapters": "./dist/adapters/index.js",
    "./adapters/vercel": "./dist/adapters/vercel.js",
    "./adapters/e2b": "./dist/adapters/e2b.js",
    "./adapters/daytona": "./dist/adapters/daytona.js",
    "./adapters/docker": "./dist/adapters/docker.js",
    "./adapters/ssh": "./dist/adapters/ssh.js",
    "./policies": "./dist/policies/index.js",
    "./testing": "./dist/testing/index.js"
  },
  "peerDependencies": {
    "@vercel/sandbox": "^1.0.0",
    "@e2b/code-interpreter": "^1.2.0",
    "@daytonaio/sdk": "^0.12.0 || ^1.0.0",
    "dockerode": "^4.0.0",
    "ssh2": "^1.16.0"
  },
  "peerDependenciesMeta": {
    "@vercel/sandbox": { "optional": true },
    "@e2b/code-interpreter": { "optional": true },
    "@daytonaio/sdk": { "optional": true },
    "dockerode": { "optional": true },
    "ssh2": { "optional": true }
  },
  "dependencies": {
    "zod": "^3.24.0",
    "js-yaml": "^4.1.0"
  }
}
```

---

## 5. Public API

### 5.1 `secureSandbox(adapter, config?)`

The primary function. Takes a `SandboxAdapter` (from any provider) and
an optional config with policy. Returns a `SecuredSandbox`.

```ts
function secureSandbox(
  adapter: SandboxAdapter,
  config?: SecureConfig,
): Promise<SecuredSandbox>;

interface SecureConfig {
  /**
   * Policy: a PolicyDefinition object or a preset function result.
   * Default: policies.devSafe()
   *
   * Use preset functions: policies.devSafe(), policies.ciStrict(),
   * policies.agentSandbox(). Extend with extensions:
   * policies.devSafe({ network: [{ allow: ['api.stripe.com'] }] })
   */
  policy?: PolicyDefinition;

  /** Workspace root inside the sandbox. Default: '/workspace'. */
  workspace?: string;

  /** Watchtower event sink URL. Optional. */
  watchtower?: string;

  /**
   * How to get the agentsh binary into the sandbox.
   *
   * - 'preinstalled': Binary already exists (snapshot or baked image).
   *    Skips download. Throws if not found at expected path.
   * - 'download': Download from GitHub releases inside the sandbox.
   *    Requires curl and tar in the sandbox. Default.
   * - 'upload': Library downloads the binary on the host first (from
   *    agentshBinaryUrl or the default GitHub releases URL), verifies
   *    its checksum, then uploads it into the sandbox via
   *    adapter.writeFile(). Useful when the sandbox has no outbound
   *    network. The host must have network access to the binary source.
   *
   * Default: 'download'
   */
  installStrategy?: 'preinstalled' | 'download' | 'upload';

  /** Override agentsh binary version. Default: pinned per library release. */
  agentshVersion?: string;

  /** Override agentsh binary architecture. Default: auto-detected. */
  agentshArch?: 'linux_amd64' | 'linux_arm64';

  /** Override agentsh binary download URL (for 'download' strategy). */
  agentshBinaryUrl?: string;

  /** Override SHA256 checksum. Use with custom binary URL. */
  agentshChecksum?: string;

  /**
   * Skip SHA256 integrity check. NOT RECOMMENDED.
   * Only use if you are providing your own binary via a trusted channel.
   */
  skipIntegrityCheck?: boolean;

  /**
   * Minimum acceptable security mode. If `agentsh detect` reports a
   * weaker mode, provisioning fails with ProvisioningError.
   * Modes from strongest to weakest: 'full', 'landlock', 'landlock-only', 'minimal'.
   * Default: undefined (accept any mode, log warning if degraded).
   */
  minimumSecurityMode?: 'full' | 'landlock' | 'landlock-only' | 'minimal';

  /**
   * Use real host paths instead of virtualizing under /workspace.
   * When true, file policy paths must match actual filesystem paths.
   * Useful for Daytona/Docker where workspace is at e.g. /home/daytona.
   * Default: false (agentsh virtualizes under /workspace).
   * (agentsh v0.13.0+)
   */
  realPaths?: boolean;

  /**
   * Make redirect rules enforced (deny execution) instead of shadowing
   * to a stub binary. When true, redirected commands are blocked outright
   * rather than silently rerouted.
   * Default: false (shadow mode — redirect to stub, audit the event).
   * (agentsh v0.13.0+)
   */
  enforceRedirects?: boolean;

  /**
   * W3C traceparent header to propagate into the agentsh session.
   * Enables distributed tracing correlation between external OTEL
   * traces and agentsh events.
   * Format: '00-<trace-id>-<span-id>-<flags>'
   * (agentsh v0.12.0+)
   */
  traceParent?: string;
}
```

**Lifecycle when called:**

See Section 10 (Provisioning Sequence) for the full step-by-step flow.

### 5.2 `createSandbox(config?)`

Convenience function for Vercel Sandbox users. Creates the sandbox AND
secures it in one call.

```ts
function createSandbox(
  config?: CreateSandboxConfig,
): Promise<SecuredSandbox>;

interface CreateSandboxConfig extends SecureConfig {
  /** Vercel Sandbox runtime. Default: 'node24'. */
  runtime?: 'node22' | 'node24' | 'python3.13';

  /** Sandbox timeout in milliseconds. Default: 300_000 (5 min). */
  timeout?: number;

  /** Number of vCPUs. Default: 2. */
  vcpus?: 1 | 2 | 4 | 8;

  /** Create from existing snapshot ID (skips binary install). */
  snapshot?: string;
}
```

Requires `@vercel/sandbox` to be installed. Throws
`MissingPeerDependencyError` if not found.

Equivalent to:

```ts
import { Sandbox } from '@vercel/sandbox';
import { secureSandbox, adapters } from '@agentsh/secure-sandbox';

const sandbox = await Sandbox.create({ runtime, timeout, vcpus, ... });
return secureSandbox(adapters.vercel(sandbox), { policy, workspace, ... });
```

---

## 6. SandboxAdapter Interface

The contract a provider adapter must satisfy. Used during provisioning
(installing agentsh, writing config, starting the server) and at runtime
as a transport layer for invoking `agentsh exec`. The adapter's `writeFile`
and `readFile` methods are only called during provisioning — never at
runtime.

Three required methods, two optional.

```ts
interface SandboxAdapter {
  /**
   * Execute a command inside the sandbox.
   * Used during provisioning for: installing binary, starting server,
   * creating session, health checks.
   */
  exec(
    cmd: string,
    args?: string[],
    opts?: {
      cwd?: string;
      sudo?: boolean;
      /** If true, don't wait for completion (for starting daemons). */
      detached?: boolean;
      /** Pass data on stdin to the command. Used at runtime for writeFile transport. */
      stdin?: string | Buffer;
    },
  ): Promise<ExecResult>;

  /**
   * Write a file inside the sandbox.
   * Used during provisioning for: writing policy, writing config,
   * uploading binary (when installStrategy is 'upload').
   */
  writeFile(
    path: string,
    content: string | Buffer,
    opts?: { sudo?: boolean },
  ): Promise<void>;

  /**
   * Read a file from the sandbox.
   * Used during provisioning for: health checks, reading session output.
   */
  readFile(path: string): Promise<string>;

  /** Stop/destroy the sandbox. Optional. */
  stop?(): Promise<void>;

  /**
   * Check if a file exists. Optional.
   * Used to detect pre-installed agentsh in snapshots.
   * If not implemented, the library uses exec('test -f ...').
   */
  fileExists?(path: string): Promise<boolean>;
}

interface ExecResult {
  stdout: string;
  stderr: string;
  exitCode: number;
}
```

---

## 7. Adapters

Each adapter is a function that takes the provider's native sandbox
object and returns a `SandboxAdapter`. Adapters are thin — typically
15-30 lines — and handle API translation only.

### 7.1 Vercel (`adapters.vercel`)

```ts
import type { Sandbox } from '@vercel/sandbox'; // type-only import

function vercel(sandbox: Sandbox): SandboxAdapter;
```

**Supported versions:** `@vercel/sandbox ^1.0.0`

**Mapping:**

| SandboxAdapter method       | Vercel SDK call |
| --------------------------- | --------------- |
| `exec(cmd, args, opts)`     | `sandbox.runCommand({ cmd, args, cwd, sudo, detached })` → read `stdout()`, `stderr()`, `.exitCode` |
| `writeFile(path, c, opts)`  | `sandbox.writeFiles([{ path, content }])` |
| `readFile(path)`            | `sandbox.readFile(path)` |
| `stop()`                    | `sandbox.stop()` |
| `fileExists(path)`          | `sandbox.runCommand({ cmd: 'test', args: ['-f', path] })` → exitCode === 0 |

### 7.2 E2B (`adapters.e2b`)

```ts
import type { Sandbox } from '@e2b/code-interpreter'; // type-only

function e2b(sandbox: Sandbox): SandboxAdapter;
```

**Supported versions:** `@e2b/code-interpreter ^1.2.0`

**Mapping:**

| SandboxAdapter method       | E2B SDK call |
| --------------------------- | ------------ |
| `exec(cmd, args, opts)`     | `sandbox.commands.run(cmd + args.join(' '), { cwd, user: sudo ? 'root' : 'user' })` |
| `writeFile(path, c, opts)`  | `sandbox.files.write(path, content)` |
| `readFile(path)`            | `sandbox.files.read(path)` |
| `stop()`                    | `sandbox.kill()` |
| `fileExists(path)`          | `sandbox.files.list(dirname(path))` → check if basename exists |

**Note:** E2B does not natively support detached processes. The adapter
uses `nohup ... &` shell wrapping for detached commands.

### 7.3 Daytona (`adapters.daytona`)

```ts
import type { Sandbox } from '@daytonaio/sdk'; // type-only

function daytona(sandbox: Sandbox): SandboxAdapter;
```

**Supported versions:** `@daytonaio/sdk ^0.12.0 || ^1.0.0`

**Mapping:**

| SandboxAdapter method       | Daytona SDK call |
| --------------------------- | ---------------- |
| `exec(cmd, args, opts)`     | `sandbox.process.executeCommand(cmd + args, { cwd })` |
| `writeFile(path, c, opts)`  | `sandbox.fs.uploadFile(path, Buffer.from(content))` |
| `readFile(path)`            | `sandbox.fs.downloadFile(path)` |
| `stop()`                    | `daytona.delete(sandbox)` (requires holding ref to client) |
| `fileExists(path)`          | `sandbox.process.executeCommand('test -f ' + path)` → exitCode |

**Note:** Daytona's `executeCommand` returns `{ exitCode, result }` where
`result` contains combined stdout. The adapter splits stdout/stderr by
running commands with `2>/tmp/_stderr; cat /tmp/_stderr >&2` redirection.

### 7.4 Docker (`adapters.docker`)

```ts
function docker(opts: DockerAdapterOpts): SandboxAdapter;

interface DockerAdapterOpts {
  /** Start a new container from this image. */
  image?: string;
  /** Attach to an existing container. */
  containerId?: string;
  /** Docker socket path. Default: '/var/run/docker.sock'. */
  socketPath?: string;
}
```

**Peer dependency:** `dockerode ^4.0.0` (optional — falls back to
`docker exec` CLI if not installed).

**Behavior:** If `image` is provided, the adapter runs
`docker run -d --rm <image> sleep infinity` and attaches. If
`containerId` is provided, it attaches directly.

### 7.5 SSH (`adapters.ssh`)

```ts
function ssh(opts: SSHAdapterOpts): SandboxAdapter;

interface SSHAdapterOpts {
  host: string;
  port?: number;            // Default: 22
  user?: string;            // Default: 'root'
  privateKey?: string;      // PEM string or path
  password?: string;
}
```

**Peer dependency:** `ssh2 ^1.16.0`

The SSH adapter runs commands via `client.exec()` and writes/reads files
via SFTP. It assumes the target is an already-isolated Linux machine
(dedicated VM, CI runner, air-gapped host) where the caller has sudo
access. **This adapter does not provide host-level isolation.**

### 7.6 Custom adapters

Developers can skip the built-in adapters entirely:

```ts
import { secureSandbox } from '@agentsh/secure-sandbox';

const sandbox = await secureSandbox({
  exec: async (cmd, args, opts) => {
    const result = await myCloudProvider.run(cmd, args);
    return { stdout: result.out, stderr: result.err, exitCode: result.code };
  },
  writeFile: async (path, content, opts) => {
    await myCloudProvider.upload(path, content);
  },
  readFile: async (path) => {
    return myCloudProvider.download(path);
  },
}, { policy: policies.devSafe() });
```

---

## 8. SecuredSandbox Interface

The return type of `secureSandbox()` and `createSandbox()`. This is what
the developer's tools interact with at runtime.

**Critical design decision:** At runtime, `SecuredSandbox` uses the adapter
exclusively as a transport layer to invoke `agentsh exec`. It never uses
provider-native file APIs, and it never executes user operations directly
through the provider runtime. The adapter's `exec` method is still called,
but only to run `agentsh exec $SID -- <command>` — the user's operation
is always mediated by agentsh's policy engine, never passed raw to the
provider.

```ts
interface SecuredSandbox {
  /**
   * Run a shell command through agentsh.
   *
   * Internally executes:
   *   adapter.exec('agentsh', ['exec', '--output', 'json', sessionId, '--', 'bash', '-c', command])
   *
   * Every subprocess spawned by this command is also policy-enforced
   * via the shell shim and agentsh's process tree tracking.
   */
  exec(
    command: string,
    opts?: { cwd?: string },
  ): Promise<ExecResult>;

  /**
   * Write a text file through agentsh. Text-only in v0.1; binary
   * file support is planned for v0.2.
   *
   * Content is base64-encoded on the host. The path and encoded
   * content are passed as arguments to avoid shell interpolation
   * of either value:
   *
   *   adapter.exec('agentsh', ['exec', sessionId, '--',
   *     'sh', '-c', 'base64 -d > "$1"', '_', path],
   *     { stdin: base64Content })
   *
   * If the adapter does not support stdin, falls back to:
   *   adapter.exec('agentsh', ['exec', sessionId, '--',
   *     'sh', '-c', 'printf "%s" "$1" | base64 -d > "$2"', '_', base64Content, path])
   *
   * The path is never interpolated into a shell string — it is passed
   * as a positional argument via `$1`/`$2`. This prevents path injection.
   *
   * This means file writes go through the shell shim and hit agentsh's
   * file policy. The raw provider writeFile API is NOT used at runtime.
   *
   * Returns success/failure + path. On deny, returns the policy message
   * instead of throwing.
   */
  writeFile(
    path: string,
    content: string,
  ): Promise<{ success: boolean; path: string; error?: string }>;

  /**
   * Read a text file through agentsh. Returns UTF-8 text content.
   * Binary file reads and large file streaming are out of scope
   * for v0.1.
   *
   * Internally executes:
   *   adapter.exec('agentsh', ['exec', sessionId, '--', 'cat', path])
   *
   * Returns content on success, error message on deny.
   */
  readFile(
    path: string,
  ): Promise<{ success: boolean; content?: string; path: string; error?: string }>;

  /** Stop the sandbox and clean up all resources. */
  stop(): Promise<void>;

  /** The agentsh session ID (for Watchtower / telemetry). */
  readonly sessionId: string;

  /**
   * The security mode detected by `agentsh detect` during provisioning.
   * 'full' = seccomp + eBPF + FUSE (100% enforcement)
   * 'landlock' = Landlock + FUSE (~85%)
   * 'landlock-only' = Landlock without FUSE (~80%)
   * 'minimal' = capability dropping + shim only (~50%)
   */
  readonly securityMode: 'full' | 'landlock' | 'landlock-only' | 'minimal';
}
```

**Error handling:** `exec()`, `writeFile()`, and `readFile()` do NOT
throw on policy denials. They return structured results with
`exitCode !== 0` or `success: false` + `error` message. This is
intentional — tools should return denial information to the model
so it can replan, not crash the agent loop.

**No raw adapter escape hatch.** The `SecuredSandbox` does not expose
the underlying `SandboxAdapter`. If the developer needs raw adapter
access, they should hold a reference to it themselves from before
calling `secureSandbox()`. This prevents accidental bypasses of the
policy layer.

---

## 9. Policy System

### 9.1 PolicyDefinition type

```ts
interface PolicyDefinition {
  file?:     FileRule[];
  network?:  NetworkRule[];
  commands?: CommandRule[];
  env?:      EnvRule[];
  dns?:      DnsRedirect[];
  connect?:  ConnectRedirect[];
}
```

### 9.2 Rule types

Each rule's top-level key IS the decision. This avoids a separate
`decision` field and reads naturally.

```ts
// ─── File rules ──────────────────────────────────────────────

type FileOp = 'read' | 'write' | 'create' | 'delete';

type FileRule =
  | { allow:      string | string[]; ops?: FileOp[] }
  | { deny:       string | string[] }
  | { redirect:   string | string[]; to: string; ops?: FileOp[] }
  | { audit:      string | string[]; ops?: FileOp[] }
  | { softDelete: string | string[] };

// ─── Network rules ───────────────────────────────────────────

type NetworkRule =
  | { allow:    string | string[]; ports?: number[] }
  | { deny:     string | string[] }
  | { redirect: string; to: string };

// ─── Command rules ───────────────────────────────────────────

type CommandRule =
  | { allow:    string | string[] }
  | { deny:     string | string[] }
  | { redirect: string | string[]; to: string | { cmd: string; args: string[] } };

// ─── Env rules ───────────────────────────────────────────────

type EnvRule = {
  commands: string[];
  allow?: string[];
  deny?: string[];
};

// ─── DNS / Connect redirects ─────────────────────────────────

type DnsRedirect = {
  match: string;       // regex pattern
  resolveTo: string;   // IP address
};

type ConnectRedirect = {
  match: string;           // host:port pattern
  redirectTo: string;      // host:port target
};
```

**Note on `approve`:** The `approve` verdict (human-in-the-loop
confirmation) exists in agentsh but is **not exposed in v0.1** of this
library. The `approve` workflow requires an approval handler interface
that defines who approves, how the request is delivered (CLI prompt,
HTTP callback, WebSocket), timeout behavior, and caching semantics.
This will be added in v0.2 with a well-defined `ApprovalHandler`
interface. For v0.1, use `deny` for operations that would otherwise
need approval — the agent will receive a clear denial message and
can explain the situation to the user.

### 9.3 Serialization

`PolicyDefinition` → agentsh YAML. The library auto-generates rule
names (`file-rule-0`, `file-rule-1`, ...) and maps shorthand to
agentsh's full format:

```ts
// Input (TypeScript shorthand)
{ deny: ['**/.env', '~/.ssh/**'] }

// Output (agentsh YAML)
file_rules:
  - name: file-rule-2
    paths: ["**/.env", "~/.ssh/**"]
    decision: deny
```

```ts
// Input
{ redirect: ['curl', 'wget'], to: { cmd: 'agentsh-fetch', args: ['--audit'] } }

// Output
command_rules:
  - name: command-rule-1
    commands: [curl, wget]
    decision: redirect
    redirect_to:
      command: agentsh-fetch
      args: ["--audit"]
```

### 9.4 Self-protection rules (system policy layer)

Self-protection rules must not be bypassable by user policy. If user
rules and self-protection rules were in the same policy file with
first-match-wins evaluation, a broad user rule like `{ allow: '/**' }`
would shadow the self-protection denials.

**Solution:** The library writes self-protection rules to a **separate
system policy directory** that agentsh evaluates in a higher-priority
layer before the user policy.

```
/etc/agentsh/
├── system/
│   └── policy.yml       ← Written by library. Read-only. Evaluated FIRST.
├── policy.yml           ← User policy. Read-only. Evaluated SECOND.
└── config.yml           ← Server config referencing both.
```

The agentsh server config declares policy evaluation order:

```yaml
policies:
  system_dir: /etc/agentsh/system  # evaluated first, always
  dir: /etc/agentsh                # user policy, evaluated second
  default: policy
```

**System policy contents (not user-configurable):**

```yaml
# /etc/agentsh/system/policy.yml
# Written by @agentsh/secure-sandbox. Evaluated before user policy.
# These rules CANNOT be overridden by user policy.

file_rules:
  - name: _system-protect-config
    paths: ["/etc/agentsh/**"]
    operations: [write, create, delete]
    decision: deny
    message: "Policy files are immutable during agent execution"

  - name: _system-protect-binary
    paths: ["/usr/local/bin/agentsh*", "/usr/bin/agentsh*"]
    operations: [write, create, delete]
    decision: deny
    message: "agentsh binary is immutable during agent execution"

  - name: _system-protect-shim-files
    paths: ["/usr/bin/agentsh-shell-shim", "/bin/bash", "/bin/sh"]
    operations: [write, create, delete]
    decision: deny
    message: "Shell and shim binaries are immutable during agent execution"

command_rules:
  - name: _system-protect-process
    commands: [kill, killall, pkill]
    args_match: ["agentsh"]
    decision: deny
    message: "Cannot terminate agentsh processes"
```

**agentsh core requirement:** This design requires agentsh to support
a `system_dir` config option that loads policies evaluated before the
standard policy directory. If this is not yet implemented in agentsh,
it must be added as a prerequisite for this library. The system policy
layer is the foundation of the self-protection guarantee.

**Note on transparent command unwrapping (v0.14.0):** agentsh now
automatically peels wrapper commands like `env`, `sudo`, `nice`, and
`nohup` before evaluating policy. This means `env kill agentsh` or
`sudo rm /etc/agentsh/policy.yml` are correctly caught by the system
policy — the library does not need to enumerate wrapper bypass patterns.

### 9.5 Presets

Four built-in presets. Each is a function that returns `PolicyDefinition`
and optionally accepts extensions. There are no string-based preset names —
presets are always function calls.

```ts
function devSafe(extensions?: Partial<PolicyDefinition>): PolicyDefinition;
function ciStrict(extensions?: Partial<PolicyDefinition>): PolicyDefinition;
function agentSandbox(extensions?: Partial<PolicyDefinition>): PolicyDefinition;
function agentDefault(extensions?: Partial<PolicyDefinition>): PolicyDefinition;
```

Usage:

```ts
import { secureSandbox, adapters, policies } from '@agentsh/secure-sandbox';

// Preset with no overrides
secureSandbox(adapter, { policy: policies.devSafe() });

// Preset with extensions
secureSandbox(adapter, {
  policy: policies.devSafe({
    network: [{ allow: ['api.stripe.com'], ports: [443] }],
  }),
});

// Fully custom (no preset)
secureSandbox(adapter, {
  policy: {
    file: [{ allow: '/workspace/**' }, { deny: '**/.env' }],
    network: [{ deny: '*' }],
  },
});
```

**Note:** The `policy` field accepts `PolicyDefinition` only — not
strings. This ensures type safety and avoids confusion between
kebab-case string names and camelCase function names.

#### `devSafe` — sensible defaults for local development

Convenience starting point, not a complete security policy. Denying
`env`/`printenv` commands does not fully prevent environment variable
access (processes can read `/proc/self/environ` or use language-level
APIs). Combine with appropriate file rules for defense in depth.

```ts
{
  file: [
    { allow: '/workspace/**', ops: ['read', 'write', 'create'] },
    { deny: ['**/.env', '**/.env.*', '**/credentials*', '~/.ssh/**'] },
    { deny: '/proc/*/environ' },
  ],
  network: [
    { allow: ['registry.npmjs.org', 'registry.yarnpkg.com'], ports: [443] },
  ],
  commands: [
    { deny: ['env', 'printenv', 'shutdown', 'reboot'] },
  ],
}
```

#### `ciStrict` — locked down for CI/CD runners

```ts
{
  file: [
    { allow: '/workspace/**' },
    { deny: '/**' },
  ],
  network: [
    { allow: ['registry.npmjs.org', 'registry.yarnpkg.com'], ports: [443] },
    { deny: '*' },
  ],
  commands: [
    { deny: ['env', 'printenv', 'shutdown', 'reboot', 'sudo'] },
  ],
}
```

#### `agentSandbox` — maximum restriction for untrusted code

```ts
{
  file: [
    { allow: '/workspace/**', ops: ['read'] },
    { deny: '/**' },
  ],
  network: [
    { deny: '*' },
  ],
  commands: [
    { deny: ['env', 'printenv', 'sudo', 'su', 'shutdown', 'reboot'] },
  ],
}
```

#### `agentDefault` — comprehensive policy for AI coding agents

Based on agentsh v0.13's `agent-default` policy. Covers privilege
escalation, system admin commands, raw network tools, destructive
git operations, and destructive file removal. This is the recommended
starting point for production AI coding agent deployments.

```ts
{
  file: [
    { allow: '/workspace/**', ops: ['read', 'write', 'create'] },
    { deny: ['/workspace/.git/config', '/workspace/.netrc'] },
    { deny: ['**/.env', '**/.env.*', '**/credentials*', '~/.ssh/**'] },
    { deny: '/proc/*/environ' },
  ],
  network: [
    { allow: ['registry.npmjs.org', 'registry.yarnpkg.com',
              'pypi.org', 'files.pythonhosted.org'], ports: [443] },
    { deny: '*' },
  ],
  commands: [
    { deny: ['env', 'printenv', 'sudo', 'su', 'doas'] },
    { deny: ['shutdown', 'reboot', 'halt', 'poweroff'] },
    { deny: ['nc', 'ncat', 'netcat', 'socat', 'telnet'] },
    { deny: ['git push --force', 'git reset --hard'] },
    { redirect: ['curl', 'wget'], to: { cmd: 'agentsh-fetch', args: ['--audit'] } },
  ],
}
```

### 9.6 `merge()` — composing and extending policies

```ts
function merge(
  base: PolicyDefinition,
  ...overrides: Partial<PolicyDefinition>[]
): PolicyDefinition;
```

Merging appends extension rules **after** base rules for each category.
Since agentsh evaluates rules top-to-bottom with first-match-wins,
overrides placed after base rules only apply to paths/domains not
already matched by the base.

To **prepend** overrides (making them take priority over base rules),
use `mergePrepend`:

```ts
function mergePrepend(
  base: PolicyDefinition,
  ...overrides: Partial<PolicyDefinition>[]
): PolicyDefinition;
```

Usage:

```ts
import { policies } from '@agentsh/secure-sandbox';

// Extend devSafe with additional network rules (appended)
const myPolicy = policies.devSafe({
  network: [
    { allow: ['api.stripe.com'], ports: [443] },
    { redirect: '*.amazonaws.com', to: 'localstack:4566' },
  ],
});

// Compose from scratch
const custom = policies.merge(
  policies.ciStrict(),
  {
    network: [{ allow: ['my-internal-api.corp'] }],
    commands: [{ allow: ['terraform'] }],
  },
);

// Prepend to override base rules (exception before the deny /**)
const withException = policies.mergePrepend(
  policies.ciStrict(),
  {
    file: [{ allow: '/etc/resolv.conf', ops: ['read'] }],
  },
);
```

### 9.7 Validation

All policy objects are validated with Zod at call time:

- `secureSandbox()` validates the policy before any sandbox operations.
- `devSafe()`, `ciStrict()`, `agentSandbox()` validate their output.
- `merge()` and `mergePrepend()` validate the merged result.

Invalid policies throw `PolicyValidationError` with a clear message
showing which rule failed and why. This fails at deploy time (or dev
server startup), not at runtime inside the sandbox.

---

## 10. Provisioning Sequence

When `secureSandbox(adapter, { policy })` is called, the following happens.
All steps use the `adapter` (raw provider API) — this is privileged setup
code. After step 14 returns, the adapter is used only as a transport for
`agentsh exec`; its `writeFile` and `readFile` methods are never called
again.

```
PHASE 1 — BINARY INSTALLATION
(skipped if installStrategy is 'preinstalled')

Step  Action                                                  Condition
─────────────────────────────────────────────────────────────────────────
  1   adapter.fileExists('/usr/local/bin/agentsh')            Always
      → If exists AND installStrategy != 'download', skip to Phase 2

  2   adapter.exec('uname -m')                               'download' or 'upload'
      → Determine linux_amd64 or linux_arm64

  3a  [download] adapter.exec('curl -sL <url> -o /tmp/agentsh.tar.gz')
      adapter.exec('tar xz -C /tmp/ -f /tmp/agentsh.tar.gz')

  3b  [upload] adapter.writeFile('/tmp/agentsh', binaryBuffer)

  4   Verify SHA256 checksum                                  Unless skipIntegrityCheck
      adapter.exec('sha256sum /tmp/agentsh')
      → Compare against pinned checksum
      → On mismatch: delete file, throw IntegrityError

  5   adapter.exec('install -m 0755 /tmp/agentsh /usr/local/bin/agentsh', { sudo: true })

  5b  Detect security capabilities:
      adapter.exec('agentsh detect --json')
      → Parse JSON → determine security mode (full/landlock/landlock-only/minimal)
      → If mode is 'minimal', log warning (limited enforcement)
      → If config.minimumSecurityMode is set and detected mode is weaker, throw ProvisioningError

  6   adapter.exec('agentsh shim install-shell ...', { sudo: true })

PHASE 2 — POLICY AND CONFIG

  7   adapter.exec('mkdir -p /etc/agentsh/system', { sudo: true })
      adapter.writeFile('/etc/agentsh/system/policy.yml', systemYaml, { sudo: true })
      (self-protection rules — see Section 9.4)

  8   adapter.writeFile('/etc/agentsh/policy.yml', userYaml, { sudo: true })
      (serialized PolicyDefinition)

  9   adapter.writeFile('/etc/agentsh/config.yml', serverConfig, { sudo: true })

 10   adapter.exec('find /etc/agentsh -type d -exec chmod 555 {} +', { sudo: true })
      adapter.exec('find /etc/agentsh -type f -exec chmod 444 {} +', { sudo: true })
      adapter.exec('chown -R root:root /etc/agentsh/', { sudo: true })

PHASE 3 — SERVER STARTUP

 11   adapter.exec('agentsh server --config /etc/agentsh/config.yml',
        { detached: true, sudo: true })

 12   Health check: poll until agentsh server is ready
      adapter.exec('agentsh health') or check socket/port
      → Retry up to 10 times with 500ms backoff
      → Throw ProvisioningError if not ready after 5s

 13   adapter.exec('agentsh session create --workspace <workspace> --policy policy')
      → Parse JSON output → extract session ID

 13b  If config.watchtower or config.traceParent is set:
      adapter.exec('curl -X PUT http://127.0.0.1:18080/sessions/<sid>/trace-context ...')
      → Set W3C traceparent for distributed tracing correlation

PHASE 4 — HANDOFF

 14   Construct SecuredSandbox wrapping adapter + session ID.
      From this point forward, SecuredSandbox.exec/writeFile/readFile
      invoke adapter.exec('agentsh exec $SID -- ...') as transport.
      The adapter's writeFile and readFile are never called again.

      Return SecuredSandbox.
```

**Total provisioning time:**
- `preinstalled`: ~1-2s (write policy + start server)
- `download` (fresh): ~6-10s (download + verify + install + start)
- `download` (snapshot with binary): ~1-2s (detected at step 1)
- `upload`: ~3-5s (upload binary + install + start)

---

## 11. Snapshot Caching

For `createSandbox()` (Vercel-specific), the library can automatically
snapshot after first provisioning:

```ts
const sandbox = await createSandbox({
  policy: policies.devSafe(),
  // First call: full bootstrap. Library snapshots automatically.
  // Subsequent calls: create from snapshot, only write policy + start server.
});
```

The snapshot ID is cached in-memory (for the server process lifetime)
and can be persisted via environment variable:

```
AGENTSH_SNAPSHOT_ID=snap_abc123
```

**Snapshot safety:** Snapshots should be used as clean templates containing
the agentsh binary and shell shim only. Implementations must avoid
snapshotting policy files, session sockets, logs, or temp files — policy
is always written fresh at provisioning time (Phase 2), ensuring each
sandbox gets the current policy even when starting from a snapshot.
The library cannot enforce snapshot contents across providers; it is the
developer's responsibility to create clean snapshots.

For other providers, snapshot management is left to the developer since
each provider has different snapshot semantics (E2B snapshots,
Daytona snapshots, Docker commit, etc.). The `installStrategy: 'preinstalled'`
option supports pre-baked images from any provider.

---

## 12. Error Handling

### 12.1 Error types

```ts
class AgentSHError extends Error { }

class PolicyValidationError extends AgentSHError {
  /** Zod issues array */
  issues: ZodIssue[];
}

class MissingPeerDependencyError extends AgentSHError {
  /** The package that needs to be installed */
  packageName: string;
  /** Supported version range */
  versionRange: string;
}

class IncompatibleProviderVersionError extends AgentSHError {
  /** Installed version */
  installed: string;
  /** Required version range */
  required: string;
}

class ProvisioningError extends AgentSHError {
  /** Which provisioning phase/step failed */
  phase: 'install' | 'policy' | 'startup' | 'session';
  /** The command that failed */
  command: string;
  /** stderr from the failed command */
  stderr: string;
}

class IntegrityError extends AgentSHError {
  /** Expected checksum */
  expected: string;
  /** Actual checksum of downloaded file */
  actual: string;
}
```

### 12.2 Provider version checking

When an adapter is first used, it checks the installed provider SDK
version against the declared supported range. If the version is
outside the range, it throws `IncompatibleProviderVersionError` with
a message like:

```
@daytonaio/sdk version 0.10.3 is not supported.
@agentsh/secure-sandbox requires @daytonaio/sdk ^0.12.0 || ^1.0.0.
Please upgrade: npm install @daytonaio/sdk@latest
```

This is checked once per process, at adapter creation time.

---

## 13. Testing

### 13.1 Mock adapter

The library ships a mock adapter for testing tools without a real sandbox:

```ts
import { mockAdapter } from '@agentsh/secure-sandbox/testing';

const mock = mockAdapter({
  commands: {
    'ls -la /workspace': { stdout: 'file1.ts\nfile2.ts', exitCode: 0 },
    'cat /workspace/.env': { stdout: '', stderr: 'denied by policy', exitCode: 1 },
  },
  files: {
    '/workspace/index.ts': 'console.log("hello")',
  },
});

const sandbox = await secureSandbox(mock, { policy: policies.devSafe() });
```

### 13.2 Integration tests

Integration tests require a real sandbox provider. They are gated
behind environment variables:

```bash
TEST_VERCEL=1 npm test
TEST_E2B=1 npm test
TEST_DAYTONA=1 npm test
TEST_DOCKER=1 npm test
```

Each integration test suite verifies:

1. Provisioning completes without error.
2. Policy file is written and read-only.
3. Self-protection: `exec('cat /etc/agentsh/policy.yml')` succeeds (policy is readable so agents can understand constraints).
4. Self-protection: `exec('rm /etc/agentsh/policy.yml')` is denied (policy is not writable/deletable).
5. Self-protection: `exec('rm /usr/local/bin/agentsh')` is denied.
6. Self-protection: `exec('mv /bin/bash /bin/bash.bak')` is denied.
7. File policy: `exec('ls /workspace')` succeeds.
8. File policy: `exec('cat /etc/shadow')` is denied.
9. Command policy: `exec('env')` is denied.
10. Network policy: `exec('curl denied-domain.com')` is denied.
11. Redirect rules produce success with rerouted destination.
12. `writeFile('/workspace/test.txt', 'hello')` succeeds.
13. `writeFile('/etc/passwd', 'evil')` is denied.
14. `readFile('/workspace/test.txt')` returns content.
15. `readFile('~/.ssh/id_rsa')` is denied.
16. Session ID is returned and valid.
17. `stop()` cleans up the sandbox.

---

## 14. Versioning and Compatibility

The library follows semver:

- **Major:** Breaking changes to `SecuredSandbox`, `SandboxAdapter`,
  `PolicyDefinition`, or `secureSandbox()` / `createSandbox()` signatures.
- **Minor:** New adapters, new policy rule types, new preset policies,
  new optional fields on existing interfaces.
- **Patch:** Bug fixes, agentsh version bumps, checksum updates, documentation.

Adapter compatibility with provider SDK versions is declared in
`peerDependencies` and checked at runtime. When a provider releases
a breaking change, we release a new minor version of `@agentsh/secure-sandbox`
with an updated adapter and an updated peer dependency range.

---

## 15. Usage Examples

### 15.1 Minimal (Vercel, default policy)

```ts
import { createSandbox } from '@agentsh/secure-sandbox';
const sandbox = await createSandbox();
const result = await sandbox.exec('node -e "console.log(42)"');
```

### 15.2 Vercel with custom policy

```ts
import { createSandbox } from '@agentsh/secure-sandbox';

const sandbox = await createSandbox({
  policy: {
    file: [{ allow: '/workspace/**' }, { deny: '**/.env' }],
    network: [{ allow: ['registry.npmjs.org'] }, { deny: '*' }],
  },
});
```

### 15.3 E2B with preset + extensions

```ts
import { Sandbox } from '@e2b/code-interpreter';
import { secureSandbox, adapters, policies } from '@agentsh/secure-sandbox';

const e2b = await Sandbox.create();
const sandbox = await secureSandbox(adapters.e2b(e2b), {
  policy: policies.agentDefault({
    network: [{ allow: ['api.stripe.com'] }],
  }),
  minimumSecurityMode: 'landlock', // fail if weaker than landlock
});

console.log(`Security mode: ${sandbox.securityMode}`);
// → "full" or "landlock" (never "minimal" due to minimumSecurityMode)
```

### 15.4 Daytona with full custom policy

```ts
import { Daytona } from '@daytonaio/sdk';
import { secureSandbox, adapters } from '@agentsh/secure-sandbox';

const daytona = new Daytona({ apiKey: process.env.DAYTONA_API_KEY });
const ws = await daytona.create({ language: 'typescript' });

const sandbox = await secureSandbox(adapters.daytona(ws), {
  policy: {
    file: [
      { allow: '/home/daytona/**' },
      { deny: ['**/.env', '**/.git/config'] },
    ],
    network: [
      { allow: ['registry.npmjs.org', 'api.github.com'], ports: [443] },
      { redirect: 'pastebin.com', to: 'paste.internal.corp' },
      { deny: '*' },
    ],
    commands: [
      { deny: ['env', 'printenv'] },
      { redirect: ['curl', 'wget'], to: { cmd: 'agentsh-fetch', args: ['--audit'] } },
    ],
  },
  workspace: '/home/daytona',
  realPaths: true,  // Daytona uses /home/daytona, not /workspace
});
```

### 15.5 Docker (self-hosted)

```ts
import { secureSandbox, adapters, policies } from '@agentsh/secure-sandbox';

const sandbox = await secureSandbox(
  adapters.docker({ image: 'node:24-slim' }),
  { policy: policies.ciStrict() },
);
```

### 15.6 Pre-baked image (any provider)

```ts
import { secureSandbox, adapters, policies } from '@agentsh/secure-sandbox';

const sandbox = await secureSandbox(
  adapters.docker({ image: 'myregistry/agent-sandbox:latest' }),
  {
    policy: policies.devSafe(),
    installStrategy: 'preinstalled', // agentsh is already in the image
  },
);
```

### 15.7 Custom adapter

```ts
import { secureSandbox, policies } from '@agentsh/secure-sandbox';

const sandbox = await secureSandbox({
  exec: async (cmd, args, opts) => {
    const result = await myCloudProvider.run(cmd, args);
    return { stdout: result.out, stderr: result.err, exitCode: result.code };
  },
  writeFile: async (path, content, opts) => {
    await myCloudProvider.upload(path, content);
  },
  readFile: async (path) => {
    return myCloudProvider.download(path);
  },
}, { policy: policies.devSafe() });
```

### 15.8 Full agent example (Vercel AI SDK)

```ts
// lib/sandbox.ts
import { Sandbox } from '@vercel/sandbox';
import { secureSandbox, adapters, policies } from '@agentsh/secure-sandbox';

const provider = adapters.vercel(await Sandbox.create({ runtime: 'node24' }));
export const sandbox = await secureSandbox(provider, {
  policy: policies.devSafe({
    network: [{ allow: ['api.github.com'] }],
  }),
});

// app/api/agent/route.ts
import { sandbox } from '@/lib/sandbox';
import { ToolLoopAgent, createAgentUIStreamResponse, tool, stepCountIs } from 'ai';
import { z } from 'zod';

const agent = new ToolLoopAgent({
  model: 'anthropic/claude-sonnet-4.5',
  tools: {
    runCommand: tool({
      description: 'Run a shell command in the secure sandbox',
      inputSchema: z.object({ command: z.string() }),
      execute: async ({ command }) => sandbox.exec(command),
    }),
    writeFile: tool({
      description: 'Write a file',
      inputSchema: z.object({ path: z.string(), content: z.string() }),
      execute: async ({ path, content }) => sandbox.writeFile(path, content),
    }),
    readFile: tool({
      description: 'Read a file',
      inputSchema: z.object({ path: z.string() }),
      execute: async ({ path }) => sandbox.readFile(path),
    }),
  },
  stopWhen: stepCountIs(25),
});

export async function POST(req) {
  const { messages } = await req.json();
  return createAgentUIStreamResponse({ agent, uiMessages: messages });
}
```

---

## 16. Future Work (v0.2+)

### 16.1 Approval handler

The `approve` verdict will be added in v0.2 with a well-defined
callback interface:

```ts
interface ApprovalHandler {
  /** Called when agentsh requires approval for an operation. */
  onApprovalRequired(request: ApprovalRequest): Promise<ApprovalResponse>;
}

interface ApprovalRequest {
  type: 'file' | 'network' | 'command';
  operation: string;        // e.g. 'delete /workspace/cache'
  message: string;          // from policy rule
  sessionId: string;
  timeout: number;          // ms before auto-deny
}

interface ApprovalResponse {
  approved: boolean;
  reason?: string;
}
```

This will integrate with AI SDK 6's `needsApproval` / `addToolApprovalResponse`
for web UIs, and with CLI prompts for terminal usage.

### 16.2 Event streaming

Real-time agentsh event streaming (file ops, network connects, process
starts) as SSE or typed AI SDK data parts for live execution panes.

### 16.3 Watchtower integration

Forwarding agentsh events to Watchtower with AI SDK step indices for
causal tracing across the model → tool → syscall → verdict chain.
W3C trace context propagation (v0.12.0) provides the `traceparent`
threading needed to correlate agentsh events with external OTEL traces.

### 16.4 Package install scanning integration

agentsh v0.12.0 includes package install security scanning across
npm, pip, uv, pnpm, yarn, and poetry. This could be surfaced in
`SecuredSandbox` as a dedicated method or as enriched metadata on
`exec()` results when an install command is detected — showing
vulnerability counts, scorecard ratings, and license concerns before
the install completes.

### 16.5 Threat intelligence feed configuration

agentsh v0.12.0 supports external threat intelligence feeds (URLhaus,
phishing lists, custom blocklists) for blocking connections to
known-malicious domains. The library could expose feed configuration
in the policy definition so developers can opt into threat feed
protection without editing agentsh config directly.

### 16.6 MCP security policy

agentsh v0.12.0 includes MCP attack surface hardening: tool-output
inspection for prompt injection, argument scanning for shell injection,
sampling request control, tool list change detection, and server binary
pinning. A future version of this library could expose MCP security
configuration in `PolicyDefinition` for agents that use MCP servers.
