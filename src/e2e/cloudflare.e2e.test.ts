import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { ENV } from './helpers.js';
import { secureSandbox } from '../api.js';
import { cloudflare } from '../adapters/cloudflare.js';
import type { SecuredSandbox } from '../core/types.js';

const canRun = !!ENV.CLOUDFLARE_WORKER_URL && !!ENV.CLOUDFLARE_API_TOKEN;

describe.skipIf(!canRun)('Cloudflare E2E', () => {
  let secured: SecuredSandbox;
  const sandboxId = `e2e-${Date.now()}`;

  beforeAll(async () => {
    const baseUrl = ENV.CLOUDFLARE_WORKER_URL!;
    const token = ENV.CLOUDFLARE_API_TOKEN!;

    // HTTP proxy that forwards exec() calls to the deployed Worker
    const sandbox = {
      async exec(command: string, opts?: { cwd?: string }) {
        const res = await fetch(`${baseUrl}/exec?id=${sandboxId}`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`,
          },
          body: JSON.stringify({ command, cwd: opts?.cwd }),
        });
        if (!res.ok) throw new Error(`Worker returned ${res.status}: ${await res.text()}`);
        return res.json();
      },
    };

    const adapter = cloudflare(sandbox);
    secured = await secureSandbox(adapter);
  }, 300_000);

  afterAll(async () => {
    await secured?.stop();
  });

  // ─── Smoke tests ──────────────────────────────────────────

  it('provisions and returns a session ID', () => {
    expect(secured.sessionId).toBeTruthy();
    expect(typeof secured.sessionId).toBe('string');
  });

  it('reports a valid security mode', () => {
    expect(['full', 'landlock', 'landlock-only', 'minimal']).toContain(
      secured.securityMode,
    );
  });

  it('exec runs a simple command', async () => {
    const result = await secured.exec('echo hello');
    expect(result.exitCode).toBe(0);
    expect(result.stdout.trim()).toBe('hello');
  });

  it('writeFile + readFile roundtrip', async () => {
    const path = '/workspace/e2e-test-file.txt';
    const content = 'e2e-roundtrip-' + Date.now();

    const writeResult = await secured.writeFile(path, content);
    expect(writeResult.success).toBe(true);

    const readResult = await secured.readFile(path);
    expect(readResult.success).toBe(true);
    if (readResult.success) {
      expect(readResult.content.trim()).toBe(content);
    }
  });

  // ─── Policy enforcement ───────────────────────────────────
  // Note: Cloudflare Containers run in Firecracker VMs whose custom kernel
  // reports 'full' security mode but may lack actual seccomp_user_notify
  // and FUSE support.  Tests for .env file deny, env/printenv blocking are
  // skipped here and covered by the Vercel E2E tests instead.

  it('allows writing to workspace', async () => {
    const result = await secured.writeFile(
      '/workspace/allowed-file.txt',
      'allowed',
    );
    expect(result.success).toBe(true);
  });

  it('blocks sudo command', async () => {
    const result = await secured.exec('sudo whoami');
    expect(result.exitCode).not.toBe(0);
  });

  it('allows curl to npm registry (if curl available)', async () => {
    const result = await secured.exec(
      'curl -s -o /dev/null -w "%{http_code}" https://registry.npmjs.org/ || echo "no-curl"',
    );
    if (!result.stdout.includes('no-curl')) {
      expect(result.stdout.trim()).toBe('200');
    }
  });

  it('blocks network to unauthorized host', async () => {
    const result = await secured.exec(
      'curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 https://evil.example.com 2>&1',
    );
    expect(result.stdout.trim()).not.toBe('200');
  });

  it('filters sensitive env vars from process environment', async () => {
    const result = await secured.exec('bash -c "echo $SECRET_KEY"');
    expect(result.stdout.trim()).toBe('');
  });
});
