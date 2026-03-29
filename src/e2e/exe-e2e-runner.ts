/**
 * Standalone exe.dev E2E test runner.
 *
 * Tests the exe adapter + full secureSandbox flow against a real exe.dev VM.
 * exe.dev VMs are accessed via SSH through the gateway — no SDK or API key needed.
 *
 * Prerequisites:
 *   - SSH access to exe.dev configured (ssh key registered)
 *   - Optionally set EXE_VM_NAME in .env.e2e (defaults to 'agentsh-e2e')
 *
 * Run: npx tsx src/e2e/exe-e2e-runner.ts
 * Or:  npm run test:e2e:exe
 */
import { config } from 'dotenv';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';

const __dirname = dirname(fileURLToPath(import.meta.url));
config({ path: resolve(__dirname, '../../.env.e2e') });

import { exe, exeDefaults } from '../adapters/exe.js';
import { secureSandbox } from '../api.js';

// ── Minimal test harness ──────────────────────────────────────

let passed = 0;
let failed = 0;

async function test(name: string, fn: () => void | Promise<void>) {
  try {
    await fn();
    passed++;
    console.log(`  \u2713 ${name}`);
  } catch (err: any) {
    failed++;
    console.log(`  \u2717 ${name}`);
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

// ── SSH helpers for VM lifecycle ─────────────────────────────

const SSH_OPTS = [
  '-o', 'StrictHostKeyChecking=no',
  '-o', 'UserKnownHostsFile=/dev/null',
  '-o', 'LogLevel=ERROR',
];

function sshExeDev(args: string, timeoutMs = 60_000): string {
  return execFileSync('ssh', [...SSH_OPTS, 'exe.dev', args], {
    encoding: 'utf-8',
    timeout: timeoutMs,
  }).trim();
}

function vmExists(name: string): boolean {
  try {
    const raw = sshExeDev('ls --json');
    const parsed = JSON.parse(raw);
    const vms = parsed.vms ?? parsed;
    return vms.some((v: any) => v.vm_name === name);
  } catch {
    return false;
  }
}

function createVM(name: string): void {
  sshExeDev(`new --name=${name} --image=ubuntu:22.04 --command=none --json`, 120_000);
}

function destroyVM(name: string): void {
  try {
    sshExeDev(`rm ${name}`);
  } catch {
    // VM may already be gone
  }
}

function waitForSSH(vmName: string, maxAttempts = 30): void {
  for (let i = 1; i <= maxAttempts; i++) {
    try {
      const result = execFileSync('ssh', [...SSH_OPTS, 'exe.dev', `ssh ${vmName} echo ssh-ready`], {
        encoding: 'utf-8',
        timeout: 10_000,
      });
      if (result.includes('ssh-ready')) return;
    } catch {
      // SSH may fail while VM is booting
    }
    if (i < maxAttempts) {
      console.log(`  Waiting for SSH... (${i}/${maxAttempts})`);
      execFileSync('sleep', ['3']);
    }
  }
  throw new Error(`SSH not reachable after ${maxAttempts} attempts`);
}

// ── Environment check ─────────────────────────────────────────

// Verify SSH access to exe.dev
try {
  sshExeDev('ls --json', 15_000);
} catch {
  console.log('\u2298 exe.dev E2E: skipped (no SSH access to exe.dev)');
  process.exit(0);
}

const VM_NAME = process.env.EXE_VM_NAME || 'agentsh-e2e';
const KEEP_VM = process.env.KEEP_VM === '1';

console.log('\u25b6 exe.dev E2E \u2014 adapter + secureSandbox tests');

// ── Create or reuse exe.dev VM ───────────────────────────────

const reused = vmExists(VM_NAME);
if (reused) {
  console.log(`  \u2192 reusing existing VM: ${VM_NAME}`);
} else {
  console.log(`  \u2192 creating exe.dev VM: ${VM_NAME}...`);
  createVM(VM_NAME);
  console.log(`  \u2192 waiting for SSH...`);
  waitForSSH(VM_NAME);
}
console.log(`  \u2192 VM ready: ${VM_NAME}`);

// ── Adapter tests ────────────────────────────────────────────

const adapter = exe(VM_NAME);

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
    env: { TEST_VAR: 'exe-e2e' },
  });
  assertEqual(result.exitCode, 0);
  assertEqual(result.stdout.trim(), 'exe-e2e');
});

await test('adapter: exec with cwd', async () => {
  const result = await adapter.exec('pwd', [], { cwd: '/tmp' });
  assertEqual(result.exitCode, 0);
  assertEqual(result.stdout.trim(), '/tmp');
});

await test('adapter: writeFile creates a file', async () => {
  await adapter.writeFile('/tmp/exe-e2e-test.txt', 'hello from e2e');
  const content = await adapter.readFile('/tmp/exe-e2e-test.txt');
  assertEqual(content, 'hello from e2e');
});

await test('adapter: readFile reads a file', async () => {
  await adapter.writeFile('/tmp/exe-e2e-read.txt', 'read-test-content');
  const content = await adapter.readFile('/tmp/exe-e2e-read.txt');
  assertEqual(content, 'read-test-content');
});

await test('adapter: writeFile + readFile roundtrip with special chars', async () => {
  const content = 'line1\nline2\ttab\n"quotes" & <brackets>';
  await adapter.writeFile('/tmp/exe-e2e-special.txt', content);
  const read = await adapter.readFile('/tmp/exe-e2e-special.txt');
  assertEqual(read, content);
});

await test('adapter: readFile throws on missing file', async () => {
  try {
    await adapter.readFile('/tmp/exe-e2e-nonexistent-xyz.txt');
    throw new Error('expected readFile to throw');
  } catch (err: any) {
    assert(err.message.includes('readFile failed'), `unexpected error: ${err.message}`);
  }
});

await test('adapter: fileExists returns true for existing file', async () => {
  await adapter.writeFile('/tmp/exe-e2e-exists.txt', 'x');
  const exists = await adapter.fileExists!('/tmp/exe-e2e-exists.txt');
  assertEqual(exists, true);
});

await test('adapter: fileExists returns false for missing file', async () => {
  const exists = await adapter.fileExists!('/tmp/exe-e2e-nonexistent-xyz');
  assertEqual(exists, false);
});

await test('adapter: detached exec returns immediately', async () => {
  const start = Date.now();
  const result = await adapter.exec('sleep', ['10'], { detached: true });
  const elapsed = Date.now() - start;
  assertEqual(result.exitCode, 0);
  assert(elapsed < 5000, `detached took too long: ${elapsed}ms`);
});

await test('adapter: stop is a no-op', async () => {
  await adapter.stop!();
  // Verify VM is still accessible
  const result = await adapter.exec('echo', ['still-alive']);
  assertEqual(result.exitCode, 0);
  assertEqual(result.stdout.trim(), 'still-alive');
});

// ── secureSandbox integration ────────────────────────────────

console.log('\n\u25b6 exe.dev E2E \u2014 secureSandbox integration');

let secured: Awaited<ReturnType<typeof secureSandbox>> | undefined;

await test('secureSandbox provisions with exeDefaults', async () => {
  try {
    secured = await secureSandbox(adapter, {
      ...exeDefaults(),
    });
  } catch (err: any) {
    // Print diagnostic info on failure
    const agentshVer = await adapter.exec('agentsh', ['--version']);
    console.log(`    agentsh: ${agentshVer.stdout.trim() || agentshVer.stderr.trim()}`);
    const serverLog = await adapter.exec('tail', ['-20', '/var/log/agentsh/server.log']);
    console.log(`    server log: ${serverLog.stdout.trim().slice(0, 500)}`);
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

  await test('blocks sudo command', async () => {
    if (secured!.securityMode === 'full') {
      const result = await secured!.exec('sudo whoami');
      assert(result.exitCode !== 0, `expected sudo to be blocked, got exit ${result.exitCode}`);
    }
  });

  await test('denies writing to .env file', async () => {
    const result = await secured!.writeFile('/root/.env', 'SECRET=leaked');
    if (secured!.securityMode === 'full') {
      assert(!result.success, 'expected .env write to be blocked');
    }
  });

  await test('allows writing to workspace (/root)', async () => {
    const result = await secured!.writeFile(
      '/root/allowed-file.txt',
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
    if (secured!.securityMode === 'full') {
      assert(result.exitCode !== 0, 'expected SSH key read to be blocked');
    }
  });

  await test('blocks raw network tools (nc)', async () => {
    const result = await secured!.exec('nc -h 2>&1 || true');
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

  await test('blocks shelley command', async () => {
    const result = await secured!.exec('shelley --help 2>&1 || true');
    if (secured!.securityMode === 'full') {
      assert(
        result.exitCode !== 0 || result.stderr.includes('blocked') || result.stderr.includes('denied'),
        'expected shelley to be blocked',
      );
    }
  });

  await test('blocks iptables command', async () => {
    const result = await secured!.exec('iptables -L 2>&1 || true');
    if (secured!.securityMode === 'full') {
      assert(
        result.exitCode !== 0 || result.stderr.includes('blocked') || result.stderr.includes('denied'),
        'expected iptables to be blocked',
      );
    }
  });
}

// ── Cleanup ──────────────────────────────────────────────────

if (!KEEP_VM && !reused) {
  console.log('\n  \u2192 destroying exe.dev VM...');
  try {
    destroyVM(VM_NAME);
    console.log('  \u2192 VM destroyed');
  } catch (err: any) {
    console.log(`  \u2192 cleanup warning: ${err.message}`);
  }
} else {
  console.log(`\n  \u2192 keeping VM: ${VM_NAME} (${reused ? 'reused' : 'KEEP_VM=1'})`);
}

// ── Summary ──────────────────────────────────────────────────

console.log(`\n${passed + failed} tests: ${passed} passed, ${failed} failed`);
if (failed > 0) {
  process.exit(1);
}
