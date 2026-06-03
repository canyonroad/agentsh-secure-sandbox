# Tensorlake Provider Support — Design

**Date:** 2026-06-02
**Status:** Approved (pending spec review)

## Goal

Add Tensorlake as a supported sandbox provider in `@agentsh/secure-sandbox`,
following the same pattern used for the other providers (an adapter + a defaults
helper + wiring + tests + docs). Tensorlake gives AI agents an isolated
Firecracker microVM; agentsh adds the runtime governance layer (command,
network, file, signal policy + DLP + audit) inside it.

The reference integration lives in `/home/eran/work/canyonroad/agentsh-tensorlake/`
(Python demo). This work ports the runtime side of that integration into the
TypeScript library.

## Background: how Tensorlake differs from the other providers

1. **Python-only SDK.** Tensorlake exposes `tensorlake.sandbox.SandboxClient`
   and has no JS/TS client — exactly like Modal. Therefore:
   - the adapter accepts an `any`-typed sandbox object (shape documented in a
     comment, not a type),
   - Tensorlake is **not** added as a peer dependency,
   - the e2e test drives a real sandbox through a Python bridge subprocess
     (mirroring `src/e2e/modal-e2e-runner.ts`).

2. **agentsh is baked into the image and auto-started by systemd.** The custom
   image (`agentsh-sandbox-v0_20_3-i1`, built by the Python `build_image.py`)
   ships the agentsh server as a systemd service and installs the shell shim at
   build time. At runtime the server is already up on `127.0.0.1:18080` and the
   shim is already in place. This maps to `installStrategy: 'running'`, which in
   `provision.ts` health-checks the server and hands off to
   `createPassthroughSandbox` in `runtime.ts` (commands run as plain `bash -c`;
   the shim enforces policy). It does **not** use the `download` / `preinstalled`
   provisioning path used by Modal / Freestyle / exe.

3. **Security-critical env injection (fail-open risk).** Tensorlake's exec API
   does not source `/etc/environment` and **replaces** the inherited environment
   when `env=` is passed. So every command must carry
   `AGENTSH_SHIM_FORCE=1`, `AGENTSH_SERVER`, `PATH`, and `HOME`, or the shim
   falls through to plain bash and **policy is silently not enforced**. In the
   Python demo the caller passes `AGENTSH_ENV` on every `sb.run`. In the library
   the **adapter** injects this on every `exec`, so enforcement cannot lapse by
   omission.

### Confirmed Tensorlake SDK shape (from the demo)

- `sb.run(cmd, args_list, env=dict, timeout=float)` → result with `.stdout`,
  `.stderr`, `.exit_code`
- `sb.write_file(path, bytes)`
- `sb.sandbox_id` (property)
- No `read_file` in the demos — reads are done via `cat` through the shim.
- Lifecycle is context-managed (`client.create_and_connect(...)`); snapshots via
  `client.snapshot_and_wait(id)`. No explicit per-sandbox `terminate()` is used
  in the demos.

## Components

### 1. Adapter — `src/adapters/tensorlake.ts`

```ts
export interface TensorlakeOptions {
  /** agentsh server address injected as AGENTSH_SERVER. Default 'http://127.0.0.1:18080'. */
  serverAddr?: string;
  /** HOME injected on every command. Default '/home/tl-user'. */
  home?: string;
  /** PATH injected on every command (Tensorlake replaces env when env= is set). */
  path?: string;
}

export function tensorlake(sandbox: any, opts?: TensorlakeOptions): SandboxAdapter
export function tensorlakeDefaults(): Partial<SecureConfig>
```

Defaults for `TensorlakeOptions` (taken from the demo's `AGENTSH_ENV`):

| Option       | Default                                                                 |
|--------------|------------------------------------------------------------------------|
| `serverAddr` | `http://127.0.0.1:18080`                                                |
| `home`       | `/home/tl-user`                                                        |
| `path`       | `/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`         |

**The shim env**, built once from `opts`:

```
{ AGENTSH_SHIM_FORCE: '1', AGENTSH_SERVER: serverAddr, PATH: path, HOME: home }
```

Adapter methods:

- **`exec(cmd, args, opts)`**
  - `env = { ...SHIM_ENV, ...opts?.env }` (caller env, e.g. `TRACEPARENT`, wins).
  - Command string built with `shellEscape(cmd, args)`; `opts.cwd` wrapped as
    `cd '<cwd>' && <cmd>` (Tensorlake `run` has no cwd parameter).
  - Calls `sandbox.run('bash', ['-c', wrapped], { env, timeout })`. (Running
    through `bash -c` is required for the shim to activate, matching the demo and
    the passthrough runtime.)
  - `detached`: fire-and-forget `nohup … >/dev/null 2>&1 &`, return exit 0
    immediately (matches modal/daytona/exe).
  - Result mapping: `exitCode = result.exit_code ?? result.exitCode ?? 0`,
    `stdout`/`stderr` default to `''`. Errors are caught and converted to a
    non-zero `ExecResult` (like modal/freestyle) — never thrown from `exec`.

- **`writeFile(path, content)`** — `sandbox.write_file(path, buffer)` (accept
  `write_file` or `writeFile` naming). Throws on failure (matches the
  `SandboxAdapter` contract for the provisioning-only write path).

- **`readFile(path)`** — try `sandbox.read_file` / `sandbox.readFile` if present;
  otherwise fall back to `exec('cat', [path])` and return stdout (throw on
  non-zero).

- **`stop()`** — best-effort `await sandbox.terminate?.() ?? sandbox.close?.()`.
  Documented that Tensorlake lifecycle is normally caller-managed via the
  context manager, so `stop` may be a no-op.

- **`fileExists(path)`** — `exec('test', ['-f', path])`, return `exitCode === 0`.

### 2. Defaults — `tensorlakeDefaults()`

```ts
{
  installStrategy: 'running',
  workspace: '/workspace',
  sessionId: 'tensorlake-shim',
  securityMode: 'full',
}
```

Rationale (documented in the function's doc comment):

- `installStrategy: 'running'` — agentsh is baked + already running; the server
  and shim are not provisioned by the library.
- **No `policy` / `serverConfig`** are returned. The `running` branch of
  `provision.ts` returns before any policy/config is written, so anything here
  would be inert and misleading. Policy + server config live in the baked image
  (`config.yaml` / `default.yaml`), built by the Python `build_image.py`.
- `sessionId: 'tensorlake-shim'` — cosmetic. The `running` path requires a
  session ID (from `config.sessionId` or `$AGENTSH_SESSION_ID`), but the baked
  shim manages sessions transparently and exposes no stable ID. Passthrough
  runtime never uses `sessionId` for exec — it is surfaced only as
  `SecuredSandbox.sessionId` for telemetry.
- `securityMode: 'full'` — set explicitly so `minimumSecurityMode` works in the
  `running` strategy (where `agentsh detect` is skipped and would otherwise
  require the caller to pass `securityMode`). `full` matches the demo's active
  backends (FUSE + seccomp + ptrace).

**No changes to `provision.ts` or `runtime.ts`** — the existing
`running` → `createPassthroughSandbox` path already provides the required
behavior (health check, then `bash -c` through the shim).

### 3. Wiring (mirrors Modal)

- `src/adapters/index.ts`: add
  `export { tensorlake, tensorlakeDefaults } from './tensorlake.js';`
- `package.json`:
  - add the `./adapters/tensorlake` entry to `exports` (types + import),
  - add script `"test:e2e:tensorlake": "npx tsx src/e2e/tensorlake-e2e-runner.ts"`,
  - **no** peer dependency / `peerDependenciesMeta` entry (Python-only SDK).
- `README.md`:
  - add Tensorlake to the provider list in the intro paragraph,
  - add a **Tensorlake** column to the "Protection by provider" table,
  - add a **Tensorlake** row to the "Primary enforcement / security mode" table,
  - add a Quick-start snippet that notes the baked-image prerequisite and points
    to the Python `build_image.py`,
  - add a short note (like the Modal/Freestyle notes) explaining the baked-image
    + `running` model and the env-injection requirement.

## Tests

### Unit — extend `src/adapters/adapters.test.ts`

Add a `describe('tensorlake adapter', …)` block asserting:

1. `exec` calls `sandbox.run('bash', ['-c', <wrapped>], { env, … })` where `env`
   contains `AGENTSH_SHIM_FORCE: '1'`, `AGENTSH_SERVER`, `PATH`, `HOME`.
2. `opts.env` is merged in and overrides the shim env (e.g. a caller
   `TRACEPARENT` survives; a caller-supplied `HOME` overrides the default).
3. `exit_code` from the SDK result maps to `ExecResult.exitCode`.
4. `opts.cwd` produces a `cd '<cwd>' && …` wrapper.
5. `writeFile` calls `sandbox.write_file` with a `Buffer`.
6. `TensorlakeOptions` overrides (custom `serverAddr` / `home` / `path`) appear
   in the injected env.
7. `tensorlakeDefaults()` returns `installStrategy: 'running'`,
   `workspace: '/workspace'`, a non-empty `sessionId`, and `securityMode: 'full'`.

### E2E — `src/e2e/tensorlake-e2e-runner.ts`

Standalone runner modeled on `modal-e2e-runner.ts`:

- Loads `.env.e2e`; **skips cleanly** (exit 0) if `TENSORLAKE_API_KEY` is unset
  or the `tensorlake` Python SDK is not importable.
- Spawns a long-lived Python bridge that creates a sandbox from the prebuilt
  image `agentsh-sandbox-v0_20_3-i1` via `SandboxClient.for_cloud(...)` +
  `create_and_connect(...)`, and speaks a JSON-line protocol over stdin/stdout
  (`run` / `write_file` / `terminate`).
- Exposes a JS object with `run(cmd, args, env, timeout)` / `write_file` /
  `terminate` shaped to what the adapter expects, then runs:
  - **adapter-level** tests (exec, env injection, exit codes, writeFile),
  - **`secureSandbox` integration** tests with `tensorlakeDefaults()`: provisions
    (health check passes), `securityMode` is valid, a benign command runs,
    `sudo`/`kill -9 1` are blocked, `curl https://evil.com` is blocked while an
    allowlisted domain passes, a `/workspace` write is allowed and an `/etc`
    write is denied.
- On sandbox-creation failure when the key *is* set, prints a clear hint:
  "image `agentsh-sandbox-v0_20_3-i1` not found — run build_image.py in
  agentsh-tensorlake first".
- Add `TENSORLAKE_API_KEY=` to `.env.e2e.example`.

## Out of scope

- **No TS image-builder helper.** Tensorlake's image is built by the Python
  `Image` builder (`build_image.py`); there is no JS equivalent of Freestyle's
  `VmSpec`, so the library cannot drive it. The README documents the Python
  build as a prerequisite.
- No changes to core provisioning/runtime, policy schema, or other adapters.

## Files touched

| File | Change |
|------|--------|
| `src/adapters/tensorlake.ts` | **new** — adapter + defaults |
| `src/adapters/index.ts` | add re-export |
| `src/adapters/adapters.test.ts` | add unit tests |
| `src/e2e/tensorlake-e2e-runner.ts` | **new** — Python-bridge e2e |
| `package.json` | add `exports` entry + `test:e2e:tensorlake` script |
| `.env.e2e.example` | add `TENSORLAKE_API_KEY=` |
| `README.md` | provider list, tables, quick-start, note |

## Verification

- `npm run typecheck` and `npm test` pass (unit tests, including the new ones).
- `npm run build` succeeds (new export path emitted).
- E2E (`npm run test:e2e:tensorlake`) is gated on credentials + prebuilt image;
  run manually when available.
