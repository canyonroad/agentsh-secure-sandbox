/**
 * Standalone Freestyle E2E test runner.
 *
 * Tests the freestyle adapter + full secureSandbox flow against a real
 * Freestyle VM. Uses configureFreestyleSpec to bake agentsh into the VM
 * at snapshot time, then runs at installStrategy: 'preinstalled'.
 *
 * Prerequisites:
 *   - freestyle-sandboxes installed
 *   - FREESTYLE_API_KEY environment variable set
 *
 * Run: npx tsx src/e2e/freestyle-e2e-runner.ts
 * Or:  npm run test:e2e:freestyle
 */
import { config } from 'dotenv';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

const __dirname = dirname(fileURLToPath(import.meta.url));
config({ path: resolve(__dirname, '../../.env.e2e') });

import { freestyle, freestyleDefaults, configureFreestyleSpec } from '../adapters/freestyle.js';
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

const FREESTYLE_API_KEY = process.env.FREESTYLE_API_KEY;

if (!FREESTYLE_API_KEY) {
  console.log('⊘ Freestyle E2E: skipped (missing FREESTYLE_API_KEY)');
  process.exit(0);
}

const require = createRequire(import.meta.url);
let sdkAvailable = false;
try { require.resolve('freestyle-sandboxes'); sdkAvailable = true; } catch {}

if (!sdkAvailable) {
  console.log('⊘ Freestyle E2E: skipped (freestyle-sandboxes not installed)');
  process.exit(0);
}

console.log('▶ Freestyle E2E — adapter + secureSandbox tests');

// ── Create Freestyle VM ───────────────────────────────────────

const fsMod = await import('freestyle-sandboxes');
const FreestyleClass = (fsMod as any).Freestyle;
const fsClient = new FreestyleClass({ apiKey: FREESTYLE_API_KEY });
const VmSpec = (fsMod as any).VmSpec;

console.log('  → creating Freestyle VM with agentsh baked in...');

const spec = configureFreestyleSpec(new VmSpec()).snapshot();
const created = await fsClient.vms.create({ spec });
const vm = created.vm ?? created;

console.log(`  → VM running: ${vm.vmId}`);

// Wait for agentsh service to become healthy (up to 60s)
console.log('  → waiting for agentsh server health...');
let ready = false;
for (let i = 0; i < 60; i++) {
  try {
    const r = await vm.exec({ command: 'curl -sf http://127.0.0.1:18080/health', timeoutMs: 5000 });
    if ((r?.stdout ?? '').trim() === 'ok') { ready = true; break; }
  } catch { /* still booting */ }
  await new Promise(res => setTimeout(res, 1000));
}
if (!ready) {
  console.error('  ✗ agentsh did not become healthy after 60s');
  try {
    const logs = await vm.exec({ command: 'tail -50 /var/log/agentsh/server.log', timeoutMs: 5000 });
    console.error(`    server log:\n${logs?.stdout ?? ''}`);
  } catch {}
  try { await vm.stop(); } catch {}
  process.exit(1);
}
console.log('  → agentsh healthy');

// ── Adapter tests ────────────────────────────────────────────

const adapter = freestyle(vm);

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
    env: { TEST_VAR: 'freestyle-e2e' },
  });
  assertEqual(result.exitCode, 0);
  assertEqual(result.stdout.trim(), 'freestyle-e2e');
});

await test('adapter: exec with cwd', async () => {
  const result = await adapter.exec('pwd', [], { cwd: '/tmp' });
  assertEqual(result.exitCode, 0);
  assertEqual(result.stdout.trim(), '/tmp');
});

await test('adapter: writeFile + readFile roundtrip', async () => {
  const content = 'line1\nline2\ttab\n"quotes" & <brackets>';
  await adapter.writeFile('/tmp/freestyle-e2e.txt', content);
  const read = await adapter.readFile('/tmp/freestyle-e2e.txt');
  assertEqual(read, content);
});

await test('adapter: fileExists detects pre-installed agentsh', async () => {
  const exists = await adapter.fileExists!('/usr/local/bin/agentsh');
  assertEqual(exists, true);
});

// ── secureSandbox integration ────────────────────────────────

console.log('\n▶ Freestyle E2E — secureSandbox integration');

let secured: Awaited<ReturnType<typeof secureSandbox>> | undefined;

await test('secureSandbox provisions with freestyleDefaults (preinstalled)', async () => {
  secured = await secureSandbox(adapter, {
    ...freestyleDefaults(),
    installStrategy: 'preinstalled',
  });
  assert(secured.sessionId, 'expected session ID');
  console.log(`    session: ${secured.sessionId}`);
  console.log(`    mode:    ${secured.securityMode}`);
});

if (secured) {
  await test('exec runs a simple command', async () => {
    const result = await secured!.exec('echo hello');
    assertEqual(result.exitCode, 0);
    assertEqual(result.stdout.trim(), 'hello');
  });

  await test('writeFile + readFile roundtrip in /home/user', async () => {
    const path = '/home/user/e2e-roundtrip.txt';
    const content = 'freestyle-' + Date.now();
    const w = await secured!.writeFile(path, content);
    assert(w.success, `writeFile failed: ${JSON.stringify(w)}`);
    const r = await secured!.readFile(path);
    assert(r.success, `readFile failed: ${JSON.stringify(r)}`);
    if (r.success) assertEqual(r.content.trim(), content);
  });

  await test('denies writing to /home/user/.env (full mode only)', async () => {
    // File deny rules on writeFile only enforce in 'full' mode (FUSE).
    // Freestyle kernels lack Yama, so seccomp file_monitor is disabled and
    // the sandbox settles into 'landlock' or 'minimal' mode where the
    // agentsh writeFile HTTP API is not subject to FUSE-level deny rules.
    // The deny rule is still enforced for shim-mediated writes via exec().
    if (secured!.securityMode === 'full') {
      const result = await secured!.writeFile('/home/user/.env', 'SECRET=leaked');
      assert(!result.success, 'expected .env write to be blocked');
    } else {
      console.log(`    (skipped: securityMode=${secured!.securityMode}, not 'full')`);
    }
  });

  await test('blocks sudo command', async () => {
    const result = await secured!.exec('sudo whoami');
    assert(result.exitCode !== 0, `expected sudo to be blocked, got exit ${result.exitCode}`);
  });

  await test('allows curl to npm registry', async () => {
    const result = await secured!.exec(
      'curl -s -o /dev/null -w "%{http_code}" https://registry.npmjs.org/',
    );
    assertEqual(result.stdout.trim(), '200');
  });

  await test('blocks curl to unlisted domain', async () => {
    const result = await secured!.exec(
      'curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 https://example.com 2>&1',
    );
    assert(result.stdout.trim() !== '200', 'expected example.com to be blocked');
  });
}

// ── Cleanup ──────────────────────────────────────────────────

console.log('\n  → stopping Freestyle VM...');
try {
  await vm.stop();
  console.log('  → VM stopped');
} catch (err: any) {
  console.log(`  → stop warning: ${err.message}`);
}

// ── Summary ──────────────────────────────────────────────────

console.log(`\n${passed + failed} tests: ${passed} passed, ${failed} failed`);
if (failed > 0) {
  process.exit(1);
}
