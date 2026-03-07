import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { ENV } from './helpers.js';
import { secureSandbox } from '../api.js';
import { cloudflare } from '../adapters/cloudflare.js';
import type { SecuredSandbox } from '../core/types.js';

// @cloudflare/sandbox requires a Workers runtime and cannot be imported in Node.js.
// Gate on both the token AND a successful dynamic import probe.
let sdkAvailable = false;
try { await import('@cloudflare/sandbox'); sdkAvailable = true; } catch {}

const canRun = !!ENV.CLOUDFLARE_API_TOKEN && sdkAvailable;

describe.skipIf(!canRun)('Cloudflare E2E', () => {
  let secured: SecuredSandbox;
  let rawSandbox: any;

  beforeAll(async () => {
    const { getSandbox } = await import('@cloudflare/sandbox');
    // getSandbox requires a DurableObjectNamespace binding from Workers runtime.
    // When running in a Cloudflare test environment, env.Sandbox would be provided.
    rawSandbox = getSandbox((globalThis as any).env?.Sandbox, 'e2e-test');

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
