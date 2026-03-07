import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createRequire } from 'node:module';
import { ENV } from './helpers.js';
import { secureSandbox } from '../api.js';
import { cloudflare } from '../adapters/cloudflare.js';
import type { SecuredSandbox } from '../core/types.js';

const require = createRequire(import.meta.url);
let sdkAvailable = false;
try { require.resolve('@cloudflare/sandbox'); sdkAvailable = true; } catch {}

const canRun = !!ENV.CLOUDFLARE_API_TOKEN && sdkAvailable;

describe.skipIf(!canRun)('Cloudflare E2E', () => {
  let secured: SecuredSandbox;
  let rawSandbox: any;

  beforeAll(async () => {
    // Cloudflare containers require a Worker/Durable Object runtime context.
    // This test assumes the SDK exposes a create/connect method.
    const cf = await import('@cloudflare/sandbox');
    rawSandbox = await (cf as any).Sandbox.create();

    const adapter = cloudflare(rawSandbox);
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

  it('denies writing to .env file (full/landlock mode)', async () => {
    if (secured.securityMode === 'full' || secured.securityMode === 'landlock') {
      const result = await secured.writeFile('/workspace/.env', 'SECRET=leaked');
      expect(result.success).toBe(false);
    }
  });

  it('allows writing to workspace', async () => {
    const result = await secured.writeFile(
      '/workspace/allowed-file.txt',
      'allowed',
    );
    expect(result.success).toBe(true);
  });

  it('blocks sudo command (full/landlock mode)', async () => {
    if (secured.securityMode === 'full' || secured.securityMode === 'landlock') {
      const result = await secured.exec('sudo whoami');
      expect(result.exitCode).not.toBe(0);
    }
  });
});
