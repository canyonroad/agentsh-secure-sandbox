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
// If the bridge already exited (e.g. sandbox creation failed), skip the
// terminate round-trip — otherwise send() would block for its full timeout.
if (bridge.exitCode === null) {
  await send({ cmd: 'terminate' }).catch(() => {});
}
bridge.kill();

// ── Summary ──────────────────────────────────────────────────

console.log(`\n${passed + failed} tests: ${passed} passed, ${failed} failed`);
if (failed > 0) {
  process.exit(1);
}
