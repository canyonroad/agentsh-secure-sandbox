/**
 * Standalone Sprites E2E test runner.
 *
 * Tests the sprites adapter against a real Fly Sprites instance.
 * Runs as a plain Node.js script because @fly/sprites uses native WebSocket
 * which doesn't work under test runners (vitest, node --test).
 *
 * Run: npx tsx src/e2e/sprites-e2e-runner.ts
 * Or:  npm run test:e2e:sprites
 */
import { config } from 'dotenv';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
config({ path: resolve(__dirname, '../../.env.e2e') });

import { sprites } from '../adapters/sprites.js';

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

function assertIncludes(haystack: string, needle: string) {
  if (!haystack.includes(needle))
    throw new Error(`expected ${JSON.stringify(haystack)} to include ${JSON.stringify(needle)}`);
}

// ── Environment check ─────────────────────────────────────────

const SPRITES_TOKEN = process.env.SPRITES_TOKEN;
const SPRITES_ORG = process.env.SPRITES_ORG;
const SPRITES_NAME = process.env.SPRITES_NAME;
const FLY_API_TOKEN = process.env.FLY_API_TOKEN;

if (!SPRITES_NAME || !(SPRITES_TOKEN || FLY_API_TOKEN)) {
  console.log('⊘ Sprites E2E: skipped (missing SPRITES_NAME or SPRITES_TOKEN/FLY_API_TOKEN)');
  process.exit(0);
}

console.log('▶ Sprites E2E — adapter tests');

// ── Connect ───────────────────────────────────────────────────

const { SpritesClient } = await import('@fly/sprites');

let token = SPRITES_TOKEN;
if (!token && FLY_API_TOKEN && SPRITES_ORG) {
  token = await SpritesClient.createToken(FLY_API_TOKEN, SPRITES_ORG);
}
if (!token) {
  console.error('  ✗ No valid token available');
  process.exit(1);
}

const client = new SpritesClient(token);
const sprite = client.sprite(SPRITES_NAME!);

// Quick connectivity check
console.log('  → connecting to sprite...');
const ping = await sprite.exec('echo pong');
assert(String(ping.stdout).trim() === 'pong', 'sprite not reachable');
console.log('  → connected');

// Create adapter
const adapter = sprites(sprite);

// ── Adapter: exec ─────────────────────────────────────────────

await test('exec runs a simple command', async () => {
  const result = await adapter.exec('echo', ['hello']);
  assertEqual(result.exitCode, 0);
  assertEqual(result.stdout.trim(), 'hello');
});

await test('exec returns non-zero exit on failure', async () => {
  const result = await adapter.exec('ls', ['/nonexistent-path-xyz']);
  assert(result.exitCode !== 0, 'expected non-zero exit code');
  // Note: sprites SDK puts error output in stdout, not stderr
  assert(result.stdout.length > 0 || result.stderr.length > 0, 'expected error output');
});

await test('exec with env vars', async () => {
  const result = await adapter.exec('sh', ['-c', 'echo $TEST_VAR'], {
    env: { TEST_VAR: 'sprites-e2e' },
  });
  assertEqual(result.exitCode, 0);
  assertEqual(result.stdout.trim(), 'sprites-e2e');
});

await test('exec with sudo prefix', async () => {
  const result = await adapter.exec('whoami', [], { sudo: true });
  // May fail if sudo not available, but should at least try with sudo prefix
  // Just verify no crash
  assert(typeof result.exitCode === 'number', 'expected numeric exitCode');
});

// ── Adapter: writeFile + readFile ─────────────────────────────

await test('writeFile creates a file', async () => {
  await adapter.writeFile('/tmp/sprites-e2e-test.txt', 'hello from e2e');
  // Verify via exec
  const result = await adapter.exec('cat', ['/tmp/sprites-e2e-test.txt']);
  assertEqual(result.stdout, 'hello from e2e');
});

await test('readFile reads a file', async () => {
  await adapter.writeFile('/tmp/sprites-e2e-read.txt', 'read-test-content');
  const content = await adapter.readFile('/tmp/sprites-e2e-read.txt');
  assertEqual(content, 'read-test-content');
});

await test('writeFile + readFile roundtrip with special chars', async () => {
  const content = 'line1\nline2\ttab\n"quotes" & <brackets>';
  await adapter.writeFile('/tmp/sprites-e2e-special.txt', content);
  const read = await adapter.readFile('/tmp/sprites-e2e-special.txt');
  assertEqual(read, content);
});

await test('writeFile + readFile roundtrip with binary-like content', async () => {
  // Base64 approach should handle arbitrary bytes
  const content = Buffer.from([0, 1, 2, 255, 254, 253]).toString('binary');
  await adapter.writeFile('/tmp/sprites-e2e-binary.txt', content);
  const read = await adapter.readFile('/tmp/sprites-e2e-binary.txt');
  assertEqual(read, content);
});

await test('readFile throws on missing file', async () => {
  try {
    await adapter.readFile('/tmp/sprites-e2e-nonexistent-xyz.txt');
    throw new Error('expected readFile to throw');
  } catch (err: any) {
    assertIncludes(err.message, 'readFile failed');
  }
});

// ── Adapter: detached exec ────────────────────────────────────

await test('detached exec returns immediately', async () => {
  const start = Date.now();
  const result = await adapter.exec('sleep', ['10'], { detached: true });
  const elapsed = Date.now() - start;
  assertEqual(result.exitCode, 0);
  // Should return nearly instantly (< 5s), not wait for sleep 10
  assert(elapsed < 5000, `detached took too long: ${elapsed}ms`);
});

// ── Cleanup ───────────────────────────────────────────────────

// Clean up test files
await adapter.exec('rm', ['-f', '/tmp/sprites-e2e-test.txt', '/tmp/sprites-e2e-read.txt', '/tmp/sprites-e2e-special.txt', '/tmp/sprites-e2e-binary.txt']);

// ── Summary ──────────────────────────────────────────────────

console.log(`\n${passed + failed} tests: ${passed} passed, ${failed} failed`);
if (failed > 0) {
  process.exit(1);
}
