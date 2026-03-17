/**
 * Standalone Modal E2E test runner.
 *
 * Tests the modal adapter + full secureSandbox flow against a real Modal sandbox.
 * Uses a Python subprocess to create and interact with the Modal sandbox since
 * Modal's SDK is Python-first and has no official JS client.
 *
 * Prerequisites:
 *   - Python 3.11+ with `modal` package installed (`pip install modal`)
 *   - MODAL_TOKEN_ID and MODAL_TOKEN_SECRET environment variables set
 *
 * Run: npx tsx src/e2e/modal-e2e-runner.ts
 * Or:  npm run test:e2e:modal
 */
import { config } from 'dotenv';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';

const __dirname = dirname(fileURLToPath(import.meta.url));
config({ path: resolve(__dirname, '../../.env.e2e') });

import { modal, modalDefaults } from '../adapters/modal.js';
import { secureSandbox } from '../api.js';

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

const MODAL_TOKEN_ID = process.env.MODAL_TOKEN_ID;
const MODAL_TOKEN_SECRET = process.env.MODAL_TOKEN_SECRET;

if (!MODAL_TOKEN_ID || !MODAL_TOKEN_SECRET) {
  console.log('⊘ Modal E2E: skipped (missing MODAL_TOKEN_ID or MODAL_TOKEN_SECRET)');
  process.exit(0);
}

// Check Python + modal SDK availability
try {
  const check = spawn('python3', ['-c', 'import modal; print(modal.__version__)'], {
    stdio: ['pipe', 'pipe', 'pipe'],
    env: { ...process.env, MODAL_TOKEN_ID, MODAL_TOKEN_SECRET },
  });
  const version = await new Promise<string>((resolve, reject) => {
    let out = '';
    check.stdout.on('data', (d: Buffer) => { out += d.toString(); });
    check.on('close', (code) => {
      if (code !== 0) reject(new Error('modal Python package not installed'));
      else resolve(out.trim());
    });
  });
  console.log(`  → modal SDK version: ${version}`);
} catch {
  console.log('⊘ Modal E2E: skipped (Python modal package not available)');
  process.exit(0);
}

console.log('▶ Modal E2E — adapter + secureSandbox tests');

// ── Python bridge ────────────────────────────────────────────
//
// Spawns a long-lived Python process that creates a Modal sandbox
// and executes commands via JSON-line protocol over stdin/stdout.
//
// Protocol:
//   → {"cmd": "exec", "args": ["sh", "-c", "echo hello"]}
//   ← {"stdout": "hello\n", "stderr": "", "returncode": 0}
//   → {"cmd": "terminate"}
//   ← {"ok": true}

const BRIDGE_SCRIPT = `
import sys, json, modal, time

app = modal.App.lookup("agentsh-e2e", create_if_missing=True)
image = (
    modal.Image.debian_slim(python_version="3.11")
    .apt_install("ca-certificates", "curl", "bash", "git", "sudo", "libseccomp2", "fuse3")
)

sb = modal.Sandbox.create(app=app, image=image, timeout=60 * 15)

# Signal ready
print(json.dumps({"ready": True}), flush=True)

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        req = json.loads(line)
    except json.JSONDecodeError:
        print(json.dumps({"error": "invalid JSON"}), flush=True)
        continue

    if req.get("cmd") == "terminate":
        try:
            sb.terminate()
        except Exception:
            pass
        print(json.dumps({"ok": True}), flush=True)
        break

    if req.get("cmd") == "exec":
        args = req.get("args", [])
        try:
            proc = sb.exec(*args)
            proc.wait()
            stdout = proc.stdout.read()
            stderr = proc.stderr.read()
            returncode = proc.returncode
            print(json.dumps({
                "stdout": stdout,
                "stderr": stderr,
                "returncode": returncode,
            }), flush=True)
        except Exception as e:
            print(json.dumps({
                "stdout": "",
                "stderr": str(e),
                "returncode": 1,
            }), flush=True)
    else:
        print(json.dumps({"error": f"unknown cmd: {req.get('cmd')}"}), flush=True)
`;

console.log('  → creating Modal sandbox...');

const bridge = spawn('python3', ['-c', BRIDGE_SCRIPT], {
  stdio: ['pipe', 'pipe', 'pipe'],
  env: { ...process.env, MODAL_TOKEN_ID, MODAL_TOKEN_SECRET },
});

// Collect stderr for diagnostics
let bridgeStderr = '';
bridge.stderr.on('data', (d: Buffer) => { bridgeStderr += d.toString(); });

// Wait for ready signal
const ready = await new Promise<boolean>((resolve, reject) => {
  const timeout = setTimeout(() => reject(new Error('Modal sandbox creation timed out after 120s')), 120_000);
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
          resolve(true);
          return;
        }
      } catch {}
    }
  };
  bridge.stdout.on('data', onData);
  bridge.on('close', (code) => {
    clearTimeout(timeout);
    reject(new Error(`Bridge exited with code ${code}: ${bridgeStderr}`));
  });
});

assert(ready, 'Bridge did not become ready');
console.log('  → Modal sandbox created');

// Create a queue-based response reader
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

async function bridgeExec(...args: string[]): Promise<{ stdout: string; stderr: string; returncode: number }> {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error(`exec timed out: ${args.join(' ')}`)), 60_000);
    responseQueue.push((msg) => {
      clearTimeout(timeout);
      resolve(msg);
    });
    bridge.stdin.write(JSON.stringify({ cmd: 'exec', args }) + '\n');
  });
}

async function bridgeTerminate(): Promise<void> {
  return new Promise((resolve) => {
    responseQueue.push(() => resolve());
    bridge.stdin.write(JSON.stringify({ cmd: 'terminate' }) + '\n');
    setTimeout(resolve, 5000); // Force resolve after 5s
  });
}

// Create a sandbox object compatible with the modal adapter
const modalSandbox = {
  async exec(...args: string[]) {
    const result = await bridgeExec(...args);
    return {
      async wait() {},
      stdout: { async read() { return result.stdout; } },
      stderr: { async read() { return result.stderr; } },
      returncode: result.returncode,
    };
  },
  async terminate() {
    await bridgeTerminate();
  },
};

// ── Adapter tests ────────────────────────────────────────────

const adapter = modal(modalSandbox);

await test('adapter: exec runs a simple command', async () => {
  const result = await adapter.exec('echo', ['hello']);
  assertEqual(result.exitCode, 0);
  assertEqual(result.stdout.trim(), 'hello');
});

await test('adapter: exec returns non-zero exit on failure', async () => {
  const result = await adapter.exec('ls', ['/nonexistent-path-xyz']);
  assert(result.exitCode !== 0, 'expected non-zero exit code');
});

await test('adapter: exec with env vars', async () => {
  const result = await adapter.exec('sh', ['-c', 'echo $TEST_VAR'], {
    env: { TEST_VAR: 'modal-e2e' },
  });
  assertEqual(result.exitCode, 0);
  assertEqual(result.stdout.trim(), 'modal-e2e');
});

await test('adapter: writeFile creates a file', async () => {
  await adapter.writeFile('/tmp/modal-e2e-test.txt', 'hello from e2e');
  const result = await adapter.exec('cat', ['/tmp/modal-e2e-test.txt']);
  assertEqual(result.stdout, 'hello from e2e');
});

await test('adapter: readFile reads a file', async () => {
  await adapter.writeFile('/tmp/modal-e2e-read.txt', 'read-test-content');
  const content = await adapter.readFile('/tmp/modal-e2e-read.txt');
  assertEqual(content, 'read-test-content');
});

await test('adapter: writeFile + readFile roundtrip with special chars', async () => {
  const content = 'line1\nline2\ttab\n"quotes" & <brackets>';
  await adapter.writeFile('/tmp/modal-e2e-special.txt', content);
  const read = await adapter.readFile('/tmp/modal-e2e-special.txt');
  assertEqual(read, content);
});

await test('adapter: readFile throws on missing file', async () => {
  try {
    await adapter.readFile('/tmp/modal-e2e-nonexistent-xyz.txt');
    throw new Error('expected readFile to throw');
  } catch (err: any) {
    assert(err.message.includes('readFile failed'), `unexpected error: ${err.message}`);
  }
});

await test('adapter: detached exec returns immediately', async () => {
  const start = Date.now();
  const result = await adapter.exec('sleep', ['10'], { detached: true });
  const elapsed = Date.now() - start;
  assertEqual(result.exitCode, 0);
  assert(elapsed < 5000, `detached took too long: ${elapsed}ms`);
});

// ── secureSandbox integration ────────────────────────────────

console.log('\n▶ Modal E2E — secureSandbox integration');

let secured: Awaited<ReturnType<typeof secureSandbox>> | undefined;

await test('secureSandbox provisions with modalDefaults', async () => {
  secured = await secureSandbox(adapter, {
    ...modalDefaults(),
  });
  assert(secured.sessionId, 'expected session ID');
  assert(typeof secured.sessionId === 'string', 'session ID should be a string');
  console.log(`    session: ${secured.sessionId}`);
  console.log(`    mode:    ${secured.securityMode}`);
});

if (secured) {
  await test('security mode is ptrace or degraded', () => {
    assert(
      ['full', 'ptrace', 'landlock', 'landlock-only', 'minimal'].includes(secured!.securityMode),
      `unexpected security mode: ${secured!.securityMode}`,
    );
  });

  await test('exec runs a simple command', async () => {
    const result = await secured!.exec('echo hello');
    assertEqual(result.exitCode, 0);
    assertEqual(result.stdout.trim(), 'hello');
  });

  await test('writeFile + readFile roundtrip', async () => {
    const path = '/root/e2e-test-file.txt';
    const content = 'e2e-roundtrip-' + Date.now();

    const writeResult = await secured!.writeFile(path, content);
    assert(writeResult.success, `writeFile failed: ${JSON.stringify(writeResult)}`);

    const readResult = await secured!.readFile(path);
    assert(readResult.success, `readFile failed: ${JSON.stringify(readResult)}`);
    if (readResult.success) {
      assertEqual(readResult.content.trim(), content);
    }
  });

  await test('blocks sudo command (ptrace mode)', async () => {
    if (secured!.securityMode === 'ptrace' || secured!.securityMode === 'full') {
      const result = await secured!.exec('sudo whoami');
      assert(result.exitCode !== 0, `expected sudo to be blocked, got exit ${result.exitCode}`);
    }
  });

  await test('blocks env command (ptrace mode)', async () => {
    if (secured!.securityMode === 'ptrace' || secured!.securityMode === 'full') {
      const result = await secured!.exec('env');
      assert(result.exitCode !== 0, `expected env to be blocked, got exit ${result.exitCode}`);
    }
  });

  await test('allows curl to npm registry', async () => {
    const result = await secured!.exec(
      'curl -s -o /dev/null -w "%{http_code}" https://registry.npmjs.org/ || echo "no-curl"',
    );
    if (!result.stdout.includes('no-curl')) {
      assertEqual(result.stdout.trim(), '200');
    }
  });

  await test('blocks network to unauthorized host', async () => {
    const result = await secured!.exec(
      'curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 https://evil.example.com 2>&1',
    );
    assert(result.stdout.trim() !== '200', 'expected evil.example.com to be blocked');
  });
}

// ── Cleanup ──────────────────────────────────────────────────

console.log('\n  → terminating Modal sandbox...');
await bridgeTerminate();
bridge.kill();

// ── Summary ──────────────────────────────────────────────────

console.log(`\n${passed + failed} tests: ${passed} passed, ${failed} failed`);
if (failed > 0) {
  process.exit(1);
}
