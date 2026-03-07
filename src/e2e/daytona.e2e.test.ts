import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createRequire } from 'node:module';
import { ENV } from './helpers.js';
import { secureSandbox } from '../api.js';
import { daytona } from '../adapters/daytona.js';
import type { SecuredSandbox } from '../core/types.js';

const require = createRequire(import.meta.url);
let sdkAvailable = false;
try { require.resolve('@daytonaio/sdk'); sdkAvailable = true; } catch {}

const canRun = !!ENV.DAYTONA_API_KEY && sdkAvailable;

describe.skipIf(!canRun)('Daytona E2E', () => {
  let secured: SecuredSandbox;
  let rawSandbox: any;
  let daytonaClient: any;

  beforeAll(async () => {
    const mod = await import('@daytonaio/sdk');
    daytonaClient = new mod.Daytona();
    rawSandbox = await daytonaClient.create();
    const adapter = daytona(rawSandbox);
    secured = await secureSandbox(adapter);
  }, 180_000);

  afterAll(async () => {
    if (rawSandbox && daytonaClient) {
      await daytonaClient.delete(rawSandbox);
    }
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

  it('denies writing to .env file', async () => {
    const result = await secured.writeFile('/workspace/.env', 'SECRET=leaked');
    expect(result.success).toBe(false);
  });

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

  it('blocks env command', async () => {
    const result = await secured.exec('env');
    expect(result.exitCode).not.toBe(0);
  });

  it('blocks printenv command', async () => {
    const result = await secured.exec('printenv');
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
