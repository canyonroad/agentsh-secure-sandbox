# Tensorlake Provider Support — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add Tensorlake as a supported sandbox provider (`tensorlake()` adapter + `tensorlakeDefaults()`) wired into the library exactly like the other providers, with unit tests, a Python-bridge e2e runner, and docs.

**Architecture:** Tensorlake is a Python-only SDK (like Modal), so the adapter takes an `any`-typed sandbox and is not a peer dependency. agentsh is baked into the image and auto-started by systemd, so we use `installStrategy: 'running'` (passthrough mode — the shell shim enforces policy on every `bash -c`). The adapter's defining job is to inject the agentsh shim env (`AGENTSH_SHIM_FORCE`, `AGENTSH_SERVER`, `PATH`, `HOME`) on every `exec`, because Tensorlake's exec API replaces the inherited environment and would otherwise silently run policy-free.

**Tech Stack:** TypeScript, Node ESM, vitest, tsup. E2E uses a Python subprocess bridge (`tensorlake` SDK).

**Reference spec:** `docs/superpowers/specs/2026-06-02-tensorlake-provider-design.md`

---

## File Structure

| File | Responsibility |
|------|----------------|
| `src/adapters/tensorlake.ts` | **new** — `tensorlake()` adapter, `tensorlakeDefaults()`, `TensorlakeOptions` |
| `src/adapters/index.ts` | re-export `tensorlake`, `tensorlakeDefaults` |
| `src/adapters/adapters.test.ts` | unit tests for the adapter + defaults |
| `src/e2e/tensorlake-e2e-runner.ts` | **new** — standalone Python-bridge e2e runner |
| `package.json` | `exports` entry + `test:e2e:tensorlake` script |
| `.env.e2e.example` | add `TENSORLAKE_API_KEY=` |
| `README.md` | provider list, tables, quick-start, note |

---

## Task 1: Create the Tensorlake adapter

**Files:**
- Create: `src/adapters/tensorlake.ts`

- [ ] **Step 1: Write the adapter file**

Create `src/adapters/tensorlake.ts` with exactly this content:

```ts
import type { SandboxAdapter, SecureConfig, ExecResult } from '../core/types.js';
import { shellEscape } from '../core/shell.js';

/** Tunables for the agentsh shim env injected on every command. */
export interface TensorlakeOptions {
  /** Injected as AGENTSH_SERVER. Default 'http://127.0.0.1:18080'. */
  serverAddr?: string;
  /** Injected as HOME. Default '/home/tl-user' (tensorlake/ubuntu-systemd base). */
  home?: string;
  /**
   * Injected as PATH. Tensorlake's exec API replaces the inherited environment
   * when env= is set, so PATH must be restored or binaries are not found.
   * Default: standard Debian PATH.
   */
  path?: string;
}

const DEFAULT_SERVER_ADDR = 'http://127.0.0.1:18080';
const DEFAULT_HOME = '/home/tl-user';
const DEFAULT_PATH = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin';

/**
 * Wraps a Tensorlake sandbox into a SandboxAdapter.
 *
 * Tensorlake provides Firecracker microVM sandboxes via a Python-first SDK
 * (`tensorlake.sandbox.SandboxClient`) — there is no JS client, so `sandbox`
 * is typed `any`. The adapter expects an object shaped like the Python SDK:
 *   - `sandbox.run(cmd, args, { env, timeout? }): { stdout, stderr, exit_code }`
 *   - `sandbox.write_file(path, bytes)`        (or `writeFile`)
 *   - optional `sandbox.read_file(path)`       (or `readFile`)
 *   - optional `sandbox.terminate()` / `close()`
 *
 * Use with the prebuilt `agentsh-sandbox-*` image (agentsh baked in + started by
 * systemd + shell shim installed). Pair with `tensorlakeDefaults()`, which
 * selects `installStrategy: 'running'` (passthrough — the shim enforces policy).
 *
 * CRITICAL: Tensorlake's exec API does not source /etc/environment and replaces
 * the inherited environment when env= is passed. This adapter therefore injects
 * AGENTSH_SHIM_FORCE / AGENTSH_SERVER / PATH / HOME on EVERY command so the shim
 * always activates — without it, commands run as plain bash and policy is
 * silently not enforced (fail-open).
 *
 * @example
 * ```ts
 * import { secureSandbox } from '@agentsh/secure-sandbox';
 * import { tensorlake, tensorlakeDefaults } from '@agentsh/secure-sandbox/adapters/tensorlake';
 *
 * // `sb` is a connected Tensorlake sandbox (built from an agentsh-baked image)
 * const sandbox = await secureSandbox(tensorlake(sb), tensorlakeDefaults());
 * await sandbox.exec('echo hello');
 * ```
 */
export function tensorlake(sandbox: any, opts?: TensorlakeOptions): SandboxAdapter {
  const shimEnv: Record<string, string> = {
    AGENTSH_SHIM_FORCE: '1',
    AGENTSH_SERVER: opts?.serverAddr ?? DEFAULT_SERVER_ADDR,
    PATH: opts?.path ?? DEFAULT_PATH,
    HOME: opts?.home ?? DEFAULT_HOME,
  };

  function normalize(result: any): ExecResult {
    return {
      stdout: result?.stdout ?? '',
      stderr: result?.stderr ?? '',
      exitCode: result?.exit_code ?? result?.exitCode ?? 0,
    };
  }

  async function call(
    cmd: string,
    args: string[],
    env: Record<string, string>,
  ): Promise<ExecResult> {
    try {
      return normalize(await sandbox.run(cmd, args, { env }));
    } catch (err: any) {
      return {
        stdout: err?.stdout ?? '',
        stderr: err?.stderr ?? err?.message ?? String(err),
        exitCode: err?.exit_code ?? err?.exitCode ?? err?.code ?? 1,
      };
    }
  }

  return {
    async exec(cmd, args, opts) {
      // Note: opts.sudo is intentionally ignored. The agentsh policy denies the
      // sudo binary, and shimmed commands already run inside the agentsh root
      // session, so a `sudo` prefix is both unnecessary and policy-denied.
      const env = { ...shimEnv, ...opts?.env };

      if (opts?.detached) {
        const inner = shellEscape(cmd, args);
        sandbox
          .run('bash', ['-c', `nohup ${inner} > /dev/null 2>&1 &`], { env })
          .catch(() => {});
        return { stdout: '', stderr: '', exitCode: 0 };
      }

      if (opts?.cwd) {
        const inner = shellEscape(cmd, args);
        const wrapped = `cd '${opts.cwd.replace(/'/g, "'\\''")}' && ${inner}`;
        return call('bash', ['-c', wrapped], env);
      }

      // Common path: the passthrough runtime calls exec('bash', ['-c', command]),
      // which matches the Python demo's `sb.run("bash", ["-c", cmd], env=…)`.
      return call(cmd, args ?? [], env);
    },

    async writeFile(path, content) {
      const buf = Buffer.isBuffer(content) ? content : Buffer.from(content);
      const fn = sandbox.write_file ?? sandbox.writeFile;
      if (typeof fn !== 'function') {
        throw new Error('tensorlake: sandbox has no write_file/writeFile method');
      }
      await fn.call(sandbox, path, buf);
    },

    async readFile(path) {
      const fn = sandbox.read_file ?? sandbox.readFile;
      if (typeof fn === 'function') {
        const out = await fn.call(sandbox, path);
        return typeof out === 'string' ? out : Buffer.from(out).toString('utf-8');
      }
      // Tensorlake's SDK may not expose a read API — fall back to `cat`.
      const result = await call('cat', [path], shimEnv);
      if (result.exitCode !== 0) {
        throw new Error(`readFile failed (exit ${result.exitCode}): ${result.stderr}`);
      }
      return result.stdout;
    },

    async stop() {
      // Tensorlake lifecycle is normally caller-managed via the context manager
      // (`create_and_connect`); terminate if the SDK exposes it.
      if (typeof sandbox.terminate === 'function') {
        await sandbox.terminate();
      } else if (typeof sandbox.close === 'function') {
        await sandbox.close();
      }
    },

    async fileExists(path) {
      const result = await call('test', ['-f', path], shimEnv);
      return result.exitCode === 0;
    },
  };
}

/**
 * Returns Tensorlake-optimized defaults for SecureConfig.
 *
 * Key characteristics:
 * - installStrategy: 'running' — agentsh is baked into the image and started by
 *   systemd; the shell shim is installed at build time. The library does NOT
 *   download/install/start the server. provision() health-checks the running
 *   server and hands off to passthrough mode (the shim enforces policy on every
 *   `bash -c`).
 * - No `policy` / `serverConfig` are returned. The 'running' branch of
 *   provision() returns before any policy/config is written, so anything here
 *   would be inert. Policy + server config live in the baked image
 *   (config.yaml / default.yaml), built by the Python build_image.py.
 * - sessionId: 'tensorlake-shim' — cosmetic. The 'running' path requires a
 *   session ID, but the baked shim manages sessions transparently and exposes
 *   no stable ID. Passthrough runtime never uses sessionId for exec; it is
 *   surfaced only as SecuredSandbox.sessionId for telemetry.
 * - securityMode: 'full' — set explicitly so minimumSecurityMode works in the
 *   'running' strategy (where `agentsh detect` is skipped). Matches the demo's
 *   active backends (FUSE + seccomp + ptrace).
 *
 * Spread into your secureSandbox() call:
 *
 *   secureSandbox(tensorlake(sb), { ...tensorlakeDefaults(), ...yourOverrides })
 */
export function tensorlakeDefaults(): Partial<SecureConfig> {
  return {
    installStrategy: 'running',
    workspace: '/workspace',
    sessionId: 'tensorlake-shim',
    securityMode: 'full',
  };
}
```

- [ ] **Step 2: Typecheck the new file**

Run: `npm run typecheck`
Expected: PASS (no errors). If `ExecResult` import is unused-flagged, it is used by `normalize`'s return type — leave it.

- [ ] **Step 3: Commit**

```bash
git add src/adapters/tensorlake.ts
git commit -m "feat(tensorlake): add adapter and defaults"
```

---

## Task 2: Re-export from the adapters barrel

**Files:**
- Modify: `src/adapters/index.ts`

- [ ] **Step 1: Add the export line**

Append to `src/adapters/index.ts` (after the `freestyle` line):

```ts
export { tensorlake, tensorlakeDefaults } from './tensorlake.js';
```

- [ ] **Step 2: Typecheck**

Run: `npm run typecheck`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add src/adapters/index.ts
git commit -m "feat(tensorlake): export from adapters barrel"
```

---

## Task 3: Unit tests for the adapter

**Files:**
- Modify: `src/adapters/adapters.test.ts`

- [ ] **Step 1: Add the imports**

At the top of `src/adapters/adapters.test.ts`, add `tensorlake` to the value imports (after the `freestyle` import on line 10) and `tensorlakeDefaults` to the defaults imports (after the `exeDefaults` import on line 20):

```ts
import { tensorlake } from './tensorlake.js';
import { tensorlakeDefaults } from './tensorlake.js';
```

- [ ] **Step 2: Write the failing test block**

Append this `describe` block to the end of `src/adapters/adapters.test.ts`:

```ts
describe('tensorlake adapter', () => {
  it('injects the shim env and passes cmd/args straight to sandbox.run', async () => {
    const run = vi.fn(async () => ({ stdout: 'hi', stderr: '', exit_code: 0 }));
    const adapter = tensorlake({ run });
    const result = await adapter.exec('bash', ['-c', 'echo hi']);
    expect(run).toHaveBeenCalledWith(
      'bash',
      ['-c', 'echo hi'],
      expect.objectContaining({
        env: expect.objectContaining({
          AGENTSH_SHIM_FORCE: '1',
          AGENTSH_SERVER: 'http://127.0.0.1:18080',
          HOME: '/home/tl-user',
          PATH: expect.stringContaining('/usr/bin'),
        }),
      }),
    );
    expect(result).toEqual({ stdout: 'hi', stderr: '', exitCode: 0 });
  });

  it('merges opts.env over the shim env', async () => {
    const run = vi.fn(async () => ({ stdout: '', stderr: '', exit_code: 0 }));
    const adapter = tensorlake({ run });
    await adapter.exec('bash', ['-c', 'true'], {
      env: { TRACEPARENT: '00-abc-def-01', HOME: '/custom' },
    });
    const passedEnv = run.mock.calls[0][2].env;
    expect(passedEnv.TRACEPARENT).toBe('00-abc-def-01');
    expect(passedEnv.HOME).toBe('/custom');
    expect(passedEnv.AGENTSH_SHIM_FORCE).toBe('1');
  });

  it('maps exit_code to exitCode', async () => {
    const run = vi.fn(async () => ({ stdout: '', stderr: 'boom', exit_code: 126 }));
    const adapter = tensorlake({ run });
    const r = await adapter.exec('bash', ['-c', 'sudo whoami']);
    expect(r.exitCode).toBe(126);
    expect(r.stderr).toBe('boom');
  });

  it('wraps cwd in a `cd … &&` prefix via bash -c', async () => {
    const run = vi.fn(async () => ({ stdout: '', stderr: '', exit_code: 0 }));
    const adapter = tensorlake({ run });
    await adapter.exec('ls', ['-la'], { cwd: '/workspace' });
    const [cmd, args] = run.mock.calls[0];
    expect(cmd).toBe('bash');
    expect(args[0]).toBe('-c');
    expect(args[1]).toContain("cd '/workspace' &&");
    expect(args[1]).toContain('ls -la');
  });

  it('writeFile calls sandbox.write_file with a Buffer', async () => {
    const write_file = vi.fn(async () => {});
    const adapter = tensorlake({ run: vi.fn(), write_file });
    await adapter.writeFile('/workspace/a.txt', 'hello');
    expect(write_file).toHaveBeenCalledWith('/workspace/a.txt', Buffer.from('hello'));
  });

  it('honors TensorlakeOptions overrides in the injected env', async () => {
    const run = vi.fn(async () => ({ stdout: '', stderr: '', exit_code: 0 }));
    const adapter = tensorlake(
      { run },
      { serverAddr: 'http://127.0.0.1:9999', home: '/root', path: '/bin' },
    );
    await adapter.exec('bash', ['-c', 'true']);
    const env = run.mock.calls[0][2].env;
    expect(env.AGENTSH_SERVER).toBe('http://127.0.0.1:9999');
    expect(env.HOME).toBe('/root');
    expect(env.PATH).toBe('/bin');
  });

  it('tensorlakeDefaults returns running passthrough config', () => {
    const d = tensorlakeDefaults();
    expect(d.installStrategy).toBe('running');
    expect(d.workspace).toBe('/workspace');
    expect(d.sessionId).toBeTruthy();
    expect(d.securityMode).toBe('full');
  });
});
```

- [ ] **Step 3: Run the new tests**

Run: `npx vitest run src/adapters/adapters.test.ts -t tensorlake`
Expected: PASS — 7 tests under "tensorlake adapter". (Task 1 already implemented the adapter, so these pass immediately; if any fail, fix the adapter in `src/adapters/tensorlake.ts`, not the test.)

- [ ] **Step 4: Run the full unit suite to confirm nothing regressed**

Run: `npm test`
Expected: PASS (all existing tests + 7 new).

- [ ] **Step 5: Commit**

```bash
git add src/adapters/adapters.test.ts
git commit -m "test(tensorlake): unit tests for adapter and defaults"
```

---

## Task 4: package.json wiring

**Files:**
- Modify: `package.json`

- [ ] **Step 1: Add the subpath export**

In `package.json`, inside `"exports"`, after the `"./adapters/freestyle"` block, add:

```json
    "./adapters/tensorlake": {
      "types": "./dist/adapters/tensorlake.d.ts",
      "import": "./dist/adapters/tensorlake.js"
    },
```

(Keep JSON valid — the preceding `freestyle` block already ends with a comma before `"./policies"`; insert the new block between them.)

- [ ] **Step 2: Add the e2e script**

In `package.json`, inside `"scripts"`, after the `"test:e2e:freestyle"` line, add:

```json
    "test:e2e:tensorlake": "npx tsx src/e2e/tensorlake-e2e-runner.ts",
```

- [ ] **Step 3: Verify JSON validity and that the export resolves after build**

Run: `node -e "JSON.parse(require('fs').readFileSync('package.json','utf8')); console.log('ok')"`
Expected: prints `ok`

Run: `npm run build`
Expected: PASS — tsup emits `dist/adapters/tensorlake.js` and `dist/adapters/tensorlake.d.ts`.

Run: `node -e "import('@agentsh/secure-sandbox/adapters/tensorlake').then(m=>console.log(typeof m.tensorlake, typeof m.tensorlakeDefaults))" 2>/dev/null || node --input-type=module -e "import('./dist/adapters/tensorlake.js').then(m=>console.log(typeof m.tensorlake, typeof m.tensorlakeDefaults))"`
Expected: prints `function function`

- [ ] **Step 4: Commit**

```bash
git add package.json
git commit -m "build(tensorlake): add subpath export and e2e script"
```

---

## Task 5: E2E runner (Python bridge)

**Files:**
- Create: `src/e2e/tensorlake-e2e-runner.ts`
- Modify: `.env.e2e.example`

- [ ] **Step 1: Add the credential placeholder**

Append to `.env.e2e.example`:

```
# Tensorlake — requires the prebuilt agentsh image registered in your account
# (build it via build_image.py in the agentsh-tensorlake repo first)
TENSORLAKE_API_KEY=
```

- [ ] **Step 2: Write the e2e runner**

Create `src/e2e/tensorlake-e2e-runner.ts` with exactly this content:

```ts
/**
 * Standalone Tensorlake E2E test runner.
 *
 * Tests the tensorlake adapter + full secureSandbox flow against a real
 * Tensorlake sandbox. Tensorlake's SDK is Python-first (no JS client), so a
 * Python subprocess bridge creates the sandbox and relays commands over a
 * JSON-line protocol — mirroring src/e2e/modal-e2e-runner.ts.
 *
 * Prerequisites:
 *   - Python 3.11+ with the `tensorlake` package installed
 *   - TENSORLAKE_API_KEY in the environment (or .env.e2e)
 *   - The prebuilt image `agentsh-sandbox-v0_20_3-i1` registered in the account
 *     (build via build_image.py in the agentsh-tensorlake repo)
 *   - Optional: TENSORLAKE_PYTHON or a `.venv-tensorlake` in repo root
 *
 * Run: npx tsx src/e2e/tensorlake-e2e-runner.ts
 * Or:  npm run test:e2e:tensorlake
 */
import { config } from 'dotenv';
import { existsSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';

const __dirname = dirname(fileURLToPath(import.meta.url));
config({ path: resolve(__dirname, '../../.env.e2e') });

import { tensorlake, tensorlakeDefaults } from '../adapters/tensorlake.js';
import { secureSandbox } from '../api.js';

const IMAGE = 'agentsh-sandbox-v0_20_3-i1';

// ── Minimal test harness ──────────────────────────────────────

let passed = 0;
let failed = 0;

async function test(name: string, fn: () => void | Promise<void>) {
  try {
    await fn();
    passed++;
    console.log(`  ✓ ${name}`);
  } catch (err: any) {
    failed++;
    console.log(`  ✗ ${name}`);
    console.log(`    ${err.message}`);
  }
}

function assert(condition: unknown, msg: string) {
  if (!condition) throw new Error(msg);
}

function assertEqual(actual: unknown, expected: unknown) {
  if (actual !== expected)
    throw new Error(`expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
}

// ── Environment check ─────────────────────────────────────────

const TENSORLAKE_API_KEY = process.env.TENSORLAKE_API_KEY;
const TENSORLAKE_PYTHON = (() => {
  if (process.env.TENSORLAKE_PYTHON) return process.env.TENSORLAKE_PYTHON;
  const venvPython = resolve(__dirname, '../../.venv-tensorlake/bin/python3');
  return existsSync(venvPython) ? venvPython : 'python3';
})();

if (!TENSORLAKE_API_KEY) {
  console.log('⊘ Tensorlake E2E: skipped (missing TENSORLAKE_API_KEY)');
  process.exit(0);
}

// Check Python + tensorlake SDK availability
try {
  const check = spawn(TENSORLAKE_PYTHON, ['-c', 'import tensorlake; print(getattr(tensorlake, "__version__", "?"))'], {
    stdio: ['pipe', 'pipe', 'pipe'],
    env: { ...process.env },
  });
  const version = await new Promise<string>((res, rej) => {
    let out = '';
    check.stdout.on('data', (d: Buffer) => { out += d.toString(); });
    check.on('close', (code) => {
      if (code !== 0) rej(new Error('tensorlake Python package not installed'));
      else res(out.trim());
    });
  });
  console.log(`  → tensorlake SDK version: ${version}`);
} catch {
  console.log(`⊘ Tensorlake E2E: skipped (tensorlake Python package not available via ${TENSORLAKE_PYTHON})`);
  process.exit(0);
}

console.log('▶ Tensorlake E2E — adapter + secureSandbox tests');

// ── Python bridge ────────────────────────────────────────────
//
// Long-lived Python process that creates a Tensorlake sandbox from the
// prebuilt agentsh image and executes commands via a JSON-line protocol.
//
// Protocol:
//   → {"cmd":"run","args":["bash","-c","echo hi"],"env":{...}}
//   ← {"stdout":"hi\n","stderr":"","exit_code":0}
//   → {"cmd":"write_file","path":"/workspace/x","b64":"..."}
//   ← {"ok":true}
//   → {"cmd":"terminate"}
//   ← {"ok":true}

const BRIDGE_SCRIPT = `
import sys, json, base64, os
from tensorlake.sandbox import SandboxClient

client = SandboxClient.for_cloud(api_key=os.environ["TENSORLAKE_API_KEY"])
cm = client.create_and_connect(image="${IMAGE}", cpus=2.0, memory_mb=2048, timeout_secs=600)
sb = cm.__enter__()

print(json.dumps({"ready": True, "sandbox_id": getattr(sb, "sandbox_id", None)}), flush=True)

def respond(obj):
    print(json.dumps(obj), flush=True)

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        req = json.loads(line)
    except json.JSONDecodeError:
        respond({"error": "invalid JSON"})
        continue

    c = req.get("cmd")
    if c == "terminate":
        try:
            cm.__exit__(None, None, None)
        except Exception:
            pass
        respond({"ok": True})
        break
    elif c == "run":
        try:
            r = sb.run(req["args"][0], req["args"][1:], env=req.get("env") or None, timeout=60.0)
            respond({"stdout": r.stdout or "", "stderr": r.stderr or "", "exit_code": r.exit_code})
        except Exception as e:
            respond({"stdout": "", "stderr": str(e), "exit_code": 1})
    elif c == "write_file":
        try:
            sb.write_file(req["path"], base64.b64decode(req["b64"]))
            respond({"ok": True})
        except Exception as e:
            respond({"ok": False, "error": str(e)})
    else:
        respond({"error": "unknown cmd: %s" % c})
`;

console.log(`  → creating Tensorlake sandbox from ${IMAGE}...`);

const bridge = spawn(TENSORLAKE_PYTHON, ['-c', BRIDGE_SCRIPT], {
  stdio: ['pipe', 'pipe', 'pipe'],
  env: { ...process.env },
});

let bridgeStderr = '';
bridge.stderr.on('data', (d: Buffer) => { bridgeStderr += d.toString(); });

const ready = await new Promise<boolean>((res, rej) => {
  const timeout = setTimeout(() => rej(new Error('Tensorlake sandbox creation timed out after 180s')), 180_000);
  let buf = '';
  const onData = (d: Buffer) => {
    buf += d.toString();
    const lines = buf.split('\n');
    buf = lines.pop() ?? '';
    for (const line of lines) {
      if (!line.trim()) continue;
      try {
        const msg = JSON.parse(line);
        if (msg.ready) {
          clearTimeout(timeout);
          bridge.stdout.removeListener('data', onData);
          console.log(`  → sandbox_id: ${msg.sandbox_id}`);
          res(true);
          return;
        }
      } catch {}
    }
  };
  bridge.stdout.on('data', onData);
  bridge.on('close', (code) => {
    clearTimeout(timeout);
    const hint = /not found|404|image/i.test(bridgeStderr)
      ? `\n  HINT: image '${IMAGE}' not found — run build_image.py in agentsh-tensorlake first.`
      : '';
    rej(new Error(`Bridge exited with code ${code}: ${bridgeStderr}${hint}`));
  });
});

assert(ready, 'Bridge did not become ready');

// Response reader
let responseBuf = '';
const responseQueue: Array<(msg: any) => void> = [];
bridge.stdout.on('data', (d: Buffer) => {
  responseBuf += d.toString();
  const lines = responseBuf.split('\n');
  responseBuf = lines.pop() ?? '';
  for (const line of lines) {
    if (!line.trim()) continue;
    try {
      const msg = JSON.parse(line);
      const resolver = responseQueue.shift();
      if (resolver) resolver(msg);
    } catch {}
  }
});

function send(obj: any): Promise<any> {
  return new Promise((res, rej) => {
    const timeout = setTimeout(() => rej(new Error(`bridge request timed out: ${obj.cmd}`)), 90_000);
    responseQueue.push((msg) => { clearTimeout(timeout); res(msg); });
    bridge.stdin.write(JSON.stringify(obj) + '\n');
  });
}

// Sandbox object shaped for the tensorlake adapter
const tlSandbox = {
  async run(cmd: string, args: string[], opts: { env?: Record<string, string> }) {
    const r = await send({ cmd: 'run', args: [cmd, ...args], env: opts?.env });
    return { stdout: r.stdout, stderr: r.stderr, exit_code: r.exit_code };
  },
  async write_file(path: string, content: Buffer) {
    const r = await send({ cmd: 'write_file', path, b64: Buffer.from(content).toString('base64') });
    if (!r.ok) throw new Error(r.error ?? 'write_file failed');
  },
  async terminate() {
    await send({ cmd: 'terminate' });
  },
};

// ── Adapter tests ────────────────────────────────────────────

const adapter = tensorlake(tlSandbox);

await test('adapter: exec runs a simple command', async () => {
  const result = await adapter.exec('bash', ['-c', 'echo hello']);
  assertEqual(result.exitCode, 0);
  assertEqual(result.stdout.trim(), 'hello');
});

await test('adapter: exec injects shim env (whoami is root via shim session)', async () => {
  const result = await adapter.exec('bash', ['-c', 'whoami']);
  assertEqual(result.exitCode, 0);
  assert(result.stdout.trim().length > 0, 'expected a user name');
});

await test('adapter: writeFile + read back via exec', async () => {
  await adapter.writeFile('/workspace/tl-e2e.txt', 'roundtrip');
  const result = await adapter.exec('bash', ['-c', 'cat /workspace/tl-e2e.txt']);
  assertEqual(result.stdout.trim(), 'roundtrip');
});

// ── secureSandbox integration ────────────────────────────────

console.log('\n▶ Tensorlake E2E — secureSandbox integration');

let secured: Awaited<ReturnType<typeof secureSandbox>> | undefined;

await test('secureSandbox provisions with tensorlakeDefaults (running/passthrough)', async () => {
  secured = await secureSandbox(adapter, { ...tensorlakeDefaults() });
  assert(typeof secured.sessionId === 'string' && secured.sessionId.length > 0, 'expected session ID');
  console.log(`    session: ${secured.sessionId}`);
  console.log(`    mode:    ${secured.securityMode}`);
});

if (secured) {
  await test('exec runs a simple command', async () => {
    const result = await secured!.exec('echo hello');
    assertEqual(result.exitCode, 0);
    assertEqual(result.stdout.trim(), 'hello');
  });

  await test('blocks sudo (command policy)', async () => {
    const result = await secured!.exec('sudo whoami');
    assert(result.exitCode !== 0, `expected sudo blocked, got exit ${result.exitCode}`);
  });

  await test('blocks kill -9 1 (signal policy)', async () => {
    const result = await secured!.exec('kill -9 1');
    assert(result.exitCode !== 0, `expected kill blocked, got exit ${result.exitCode}`);
  });

  await test('blocks curl to evil.com (network policy)', async () => {
    const result = await secured!.exec('curl --max-time 5 -s https://evil.com');
    assert(result.exitCode !== 0, 'expected evil.com blocked');
  });

  await test('allows /workspace write, denies /etc write (file policy)', async () => {
    const ok = await secured!.exec('touch /workspace/tl-ok && echo ok');
    assertEqual(ok.stdout.trim(), 'ok');
    const denied = await secured!.exec('touch /etc/tl-evil');
    assert(denied.exitCode !== 0, 'expected /etc write to be denied');
  });
}

// ── Cleanup ──────────────────────────────────────────────────

console.log('\n  → terminating Tensorlake sandbox...');
await send({ cmd: 'terminate' }).catch(() => {});
bridge.kill();

// ── Summary ──────────────────────────────────────────────────

console.log(`\n${passed + failed} tests: ${passed} passed, ${failed} failed`);
if (failed > 0) {
  process.exit(1);
}
```

- [ ] **Step 3: Typecheck (the runner is plain tsx but should still compile)**

Run: `npx tsc --noEmit src/e2e/tensorlake-e2e-runner.ts 2>/dev/null || npm run typecheck`
Expected: PASS via `npm run typecheck` (the project tsconfig covers `src/**`).

- [ ] **Step 4: Verify the runner skips cleanly without credentials**

Run: `unset TENSORLAKE_API_KEY; npx tsx src/e2e/tensorlake-e2e-runner.ts`
Expected: prints `⊘ Tensorlake E2E: skipped (missing TENSORLAKE_API_KEY)` and exits 0.

(Full run against a real account is manual: set `TENSORLAKE_API_KEY`, ensure the image is built, then `npm run test:e2e:tensorlake`.)

- [ ] **Step 5: Commit**

```bash
git add src/e2e/tensorlake-e2e-runner.ts .env.e2e.example
git commit -m "test(tensorlake): python-bridge e2e runner"
```

---

## Task 6: README documentation

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Add Tensorlake to the intro provider list**

In `README.md` line 3, in the provider list sentence, add Tensorlake before "and [Freestyle]". Change:

```
..., [exe.dev](https://exe.dev), and [Freestyle](https://freestyle.sh).
```
to:
```
..., [exe.dev](https://exe.dev), [Freestyle](https://freestyle.sh), and [Tensorlake](https://www.tensorlake.ai/).
```

- [ ] **Step 2: Add a Tensorlake column to the protection table**

In the "Protection | Vercel | E2B | … | Freestyle |" table (around line 113), add a `Tensorlake` column header and the matching `---` separator cell, and add a cell to each protection row. Use the same marks Freestyle uses for each row (Tensorlake's enforcement profile — FUSE + seccomp + ptrace + cgroups — matches or exceeds Freestyle's), EXCEPT the network row, where eBPF is unavailable on Tensorlake's kernel (DNS-proxy only): mark the network row with the same symbol the table uses for "partial/proxy-only" if one exists, otherwise reuse the Freestyle network mark. Keep column alignment.

(Concretely: read the header row and each data row, append one cell per row. The exact glyphs — ✅ / ⚠️ / etc. — must be copied from the existing cells in that same table; do not invent new ones.)

- [ ] **Step 3: Add a Tensorlake row to the enforcement table**

In the "Provider | Primary Enforcement | Security Mode" table (around line 124-135), add after the Freestyle row:

```
| [**Tensorlake**](https://www.tensorlake.ai/) | seccomp + FUSE + ptrace (execve/openat/connect) + network proxy (DNS) + cgroups | `full` |
```

- [ ] **Step 4: Add a Tensorlake note**

After the Freestyle note (around line 145), add:

```
> **Tensorlake:** agentsh is baked into the sandbox image and started by systemd (server + shell shim installed at build time), so the library uses `installStrategy: 'running'` (passthrough — the shim enforces policy on every command). Build the image with the Python `build_image.py` in the [agentsh-tensorlake](https://github.com/canyonroad/agentsh-tensorlake) repo. Tensorlake's exec API replaces the inherited environment, so the adapter injects `AGENTSH_SHIM_FORCE` / `AGENTSH_SERVER` / `PATH` / `HOME` on every command to keep enforcement from silently lapsing. Network policy enforces via the agentsh DNS proxy (this kernel lacks BTF for eBPF).
```

- [ ] **Step 5: Add a Tensorlake quick-start snippet**

After the Freestyle quick-start block (around line 191-196), add:

```
// Tensorlake (Firecracker microVMs; Python SDK, agentsh baked into the image)
// One-time: build the image via build_image.py in the agentsh-tensorlake repo.
import { tensorlake, tensorlakeDefaults } from '@agentsh/secure-sandbox/adapters/tensorlake';
// `sb` is a connected Tensorlake sandbox built from the agentsh image
const sandbox = await secureSandbox(tensorlake(sb), tensorlakeDefaults());
await sandbox.exec('echo hello');
```

- [ ] **Step 6: Sanity-check the tables render**

Run: `grep -n "Tensorlake" README.md`
Expected: matches in the intro line, both tables, the note, and the quick-start (5+ lines). Manually confirm the protection table still has equal pipe counts per row:

Run: `awk -F'|' '/^\| (Protection|Sandbox escape|File|Network|Secret)/{print NF, $0}' README.md`
Expected: every printed row reports the same field count (NF).

- [ ] **Step 7: Commit**

```bash
git add README.md
git commit -m "docs(tensorlake): add provider to README tables and quick-start"
```

---

## Task 7: Final verification

- [ ] **Step 1: Full typecheck + unit tests + build**

Run: `npm run typecheck && npm test && npm run build`
Expected: all PASS; `dist/adapters/tensorlake.js` + `.d.ts` present.

- [ ] **Step 2: Confirm the e2e runner skips cleanly (no creds)**

Run: `unset TENSORLAKE_API_KEY; npx tsx src/e2e/tensorlake-e2e-runner.ts`
Expected: `⊘ Tensorlake E2E: skipped (missing TENSORLAKE_API_KEY)`, exit 0.

- [ ] **Step 3: Confirm parity with Modal wiring**

Run: `grep -c tensorlake src/adapters/index.ts package.json && grep -c modal src/adapters/index.ts package.json`
Expected: `tensorlake` appears in both files (index.ts: 1, package.json: ≥2 — export block + script), comparable to `modal`.

---

## Self-Review (completed during planning)

- **Spec coverage:** adapter (Task 1) ✓; defaults (Task 1) ✓; barrel export (Task 2) ✓; unit tests (Task 3) ✓; package.json export + script (Task 4) ✓; `.env.e2e.example` (Task 5) ✓; e2e runner (Task 5) ✓; README list/tables/note/quick-start (Task 6) ✓; "no peer dep" — satisfied by *not* touching `peerDependencies` (Task 4 only adds an `exports` entry + script). No TS image-builder helper — out of scope per spec.
- **Type consistency:** `tensorlake(sandbox, opts?)`, `TensorlakeOptions`, `tensorlakeDefaults()`, and the SDK shape (`run`/`write_file`/`exit_code`) are used identically in the adapter (Task 1), unit tests (Task 3), and e2e bridge (Task 5).
- **Placeholder scan:** no TBD/TODO; every code step contains full content.
```
