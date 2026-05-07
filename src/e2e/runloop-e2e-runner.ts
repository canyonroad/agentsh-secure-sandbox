/**
 * Standalone Runloop E2E test runner.
 *
 * Tests the runloop adapter + full secureSandbox flow against a real Runloop devbox.
 * Uses the Runloop JS/TS SDK to create and manage devboxes.
 *
 * Prerequisites:
 *   - @runloop/api-client installed (`npm install @runloop/api-client`)
 *   - RUNLOOP_API_KEY environment variable set
 *
 * Run: npx tsx src/e2e/runloop-e2e-runner.ts
 * Or:  npm run test:e2e:runloop
 */
import { config } from 'dotenv';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

const __dirname = dirname(fileURLToPath(import.meta.url));
config({ path: resolve(__dirname, '../../.env.e2e') });

import { runloop, runloopDefaults } from '../adapters/runloop.js';
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

const RUNLOOP_API_KEY = process.env.RUNLOOP_API_KEY;

if (!RUNLOOP_API_KEY) {
  console.log('⊘ Runloop E2E: skipped (missing RUNLOOP_API_KEY)');
  process.exit(0);
}

// Check SDK availability
const require = createRequire(import.meta.url);
let sdkAvailable = false;
try { require.resolve('@runloop/api-client'); sdkAvailable = true; } catch {}

if (!sdkAvailable) {
  console.log('⊘ Runloop E2E: skipped (@runloop/api-client not installed)');
  process.exit(0);
}

console.log('▶ Runloop E2E — adapter + secureSandbox tests');

// ── Create Runloop devbox ───────────────────────────────────────

const RunloopSdk = (await import('@runloop/api-client')).default;
const client = new RunloopSdk();

console.log('  → creating Runloop devbox...');

// Create a devbox with the default Runloop image.
// secureSandbox will download and install agentsh during provisioning.
const devbox = await client.devboxes.createAndAwaitRunning({
  launch_parameters: {
    launch_commands: [
      // Ensure sudo and fuse3 are available (needed for agentsh provisioning)
      'sudo apt-get update -qq && sudo apt-get install -y -qq fuse3 libseccomp2 > /dev/null 2>&1 || true',
    ],
  },
});

const devboxId = devbox.id;
console.log(`  → devbox running: ${devboxId}`);

// ── Adapter tests ────────────────────────────────────────────

const adapter = runloop({ client, id: devboxId });

await test('adapter: exec runs a simple command', async () => {
  const result = await adapter.exec('echo', ['hello']);
  assertEqual(result.exitCode, 0);
  assertEqual(result.stdout.trim(), 'hello');
});

await test('adapter: exec returns non-zero exit on failure', async () => {
  const result = await adapter.exec('ls', ['/nonexistent-path-xyz']);
  assert(result.exitCode !== 0, 'expected non-zero exit code');
});

await test('adapter: exec with sudo', async () => {
  const result = await adapter.exec('whoami', [], { sudo: true });
  assertEqual(result.exitCode, 0);
  assertEqual(result.stdout.trim(), 'root');
});

await test('adapter: exec with env vars', async () => {
  const result = await adapter.exec('sh', ['-c', 'echo $TEST_VAR'], {
    env: { TEST_VAR: 'runloop-e2e' },
  });
  assertEqual(result.exitCode, 0);
  assertEqual(result.stdout.trim(), 'runloop-e2e');
});

await test('adapter: exec with cwd', async () => {
  const result = await adapter.exec('pwd', [], { cwd: '/tmp' });
  assertEqual(result.exitCode, 0);
  assertEqual(result.stdout.trim(), '/tmp');
});

await test('adapter: writeFile creates a file', async () => {
  await adapter.writeFile('/tmp/runloop-e2e-test.txt', 'hello from e2e');
  const content = await adapter.readFile('/tmp/runloop-e2e-test.txt');
  assertEqual(content, 'hello from e2e');
});

await test('adapter: readFile reads a file', async () => {
  await adapter.writeFile('/tmp/runloop-e2e-read.txt', 'read-test-content');
  const content = await adapter.readFile('/tmp/runloop-e2e-read.txt');
  assertEqual(content, 'read-test-content');
});

await test('adapter: writeFile + readFile roundtrip with special chars', async () => {
  const content = 'line1\nline2\ttab\n"quotes" & <brackets>';
  await adapter.writeFile('/tmp/runloop-e2e-special.txt', content);
  const read = await adapter.readFile('/tmp/runloop-e2e-special.txt');
  assertEqual(read, content);
});

await test('adapter: readFile throws on missing file', async () => {
  try {
    await adapter.readFile('/tmp/runloop-e2e-nonexistent-xyz.txt');
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

console.log('\n▶ Runloop E2E — secureSandbox integration');

let secured: Awaited<ReturnType<typeof secureSandbox>> | undefined;

await test('secureSandbox provisions with runloopDefaults', async () => {
  try {
    secured = await secureSandbox(adapter, {
      ...runloopDefaults(),
    });
  } catch (err: any) {
    // Print diagnostic info on failure
    const agentshVer = await adapter.exec('agentsh', ['--version']);
    console.log(`    agentsh: ${agentshVer.stdout.trim() || agentshVer.stderr.trim()}`);
    const serverTest = await adapter.exec('sudo', ['agentsh', 'server', '--config', '/etc/agentsh/config.yml']);
    console.log(`    server error: ${serverTest.stderr.trim().slice(0, 300)}`);
    throw err;
  }
  assert(secured.sessionId, 'expected session ID');
  assert(typeof secured.sessionId === 'string', 'session ID should be a string');
  console.log(`    session: ${secured.sessionId}`);
  console.log(`    mode:    ${secured.securityMode}`);
});

if (secured) {
  await test('security mode is full or degraded', () => {
    assert(
      ['full', 'ptrace', 'landlock', 'landlock-only', 'minimal'].includes(secured!.securityMode),
      `unexpected security mode: ${secured!.securityMode}`,
    );
  });

  await test('exec runs a simple command', async () => {
    const versionResult = await adapter.exec('agentsh', ['--version']);
    console.log(`    agentsh binary: ${(versionResult.stdout || versionResult.stderr).trim()}`);
    const result = await secured!.exec('echo hello');
    assertEqual(result.exitCode, 0);
    assertEqual(result.stdout.trim(), 'hello');
  });

  await test('writeFile + readFile roundtrip', async () => {
    const path = '/workspace/e2e-test-file.txt';
    const content = 'e2e-roundtrip-' + Date.now();

    const writeResult = await secured!.writeFile(path, content);
    assert(writeResult.success, `writeFile failed: ${JSON.stringify(writeResult)}`);

    const readResult = await secured!.readFile(path);
    assert(readResult.success, `readFile failed: ${JSON.stringify(readResult)}`);
    if (readResult.success) {
      assertEqual(readResult.content.trim(), content);
    }
  });

  await test('blocks sudo command', async () => {
    if (secured!.securityMode === 'full') {
      const result = await secured!.exec('sudo whoami');
      assert(result.exitCode !== 0, `expected sudo to be blocked, got exit ${result.exitCode}`);
    }
  });

  await test('denies writing to .env file', async () => {
    const result = await secured!.writeFile('/workspace/.env', 'SECRET=leaked');
    if (secured!.securityMode === 'full') {
      assert(!result.success, 'expected .env write to be blocked');
    }
  });

  await test('allows writing to workspace', async () => {
    const result = await secured!.writeFile(
      '/workspace/allowed-file.txt',
      'allowed',
    );
    assert(result.success, 'expected workspace write to succeed');
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

  await test('denies reading SSH keys', async () => {
    const result = await secured!.exec('cat ~/.ssh/id_rsa 2>&1');
    // In full mode with FUSE, file access is blocked by policy
    if (secured!.securityMode === 'full') {
      assert(result.exitCode !== 0, 'expected SSH key read to be blocked');
    }
  });

  await test('blocks raw network tools (nc)', async () => {
    const result = await secured!.exec('nc -h 2>&1 || true');
    // Command should be blocked by policy
    if (secured!.securityMode === 'full') {
      assert(
        result.exitCode !== 0 || result.stderr.includes('blocked') || result.stderr.includes('denied'),
        'expected nc to be blocked',
      );
    }
  });

  await test('blocks kill command', async () => {
    const result = await secured!.exec('kill -0 1 2>&1');
    if (secured!.securityMode === 'full') {
      assert(result.exitCode !== 0, 'expected kill to be blocked');
    }
  });

  await test('filters sensitive env vars', async () => {
    const result = await secured!.exec('bash -c "echo $SECRET_KEY"');
    assertEqual(result.stdout.trim(), '');
  });
}

// ── Cleanup ──────────────────────────────────────────────────

console.log('\n  → shutting down Runloop devbox...');
try {
  await client.devboxes.shutdown(devboxId);
  console.log('  → devbox shut down');
} catch (err: any) {
  console.log(`  → shutdown warning: ${err.message}`);
}

// ── Summary ──────────────────────────────────────────────────

console.log(`\n${passed + failed} tests: ${passed} passed, ${failed} failed`);
if (failed > 0) {
  process.exit(1);
}
