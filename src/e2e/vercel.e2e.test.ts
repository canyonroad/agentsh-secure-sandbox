import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createRequire } from 'node:module';
import { ENV } from './helpers.js';
import { secureSandbox } from '../api.js';
import { vercel } from '../adapters/vercel.js';
import type { SecuredSandbox } from '../core/types.js';

const require = createRequire(import.meta.url);
let sdkAvailable = false;
try { require.resolve('@vercel/sandbox'); sdkAvailable = true; } catch {}

const canRun = !!ENV.VERCEL_TOKEN && sdkAvailable;

describe.skipIf(!canRun)('Vercel E2E', () => {
  let secured: SecuredSandbox;
  let rawSandbox: any;

  beforeAll(async () => {
    const { Sandbox } = await import('@vercel/sandbox');
    rawSandbox = await Sandbox.create({
      runtime: 'node24',
      timeout: 600_000,
      token: ENV.VERCEL_TOKEN!,
      projectId: ENV.VERCEL_PROJECT_ID!,
      teamId: ENV.VERCEL_TEAM_ID!,
    });

    // Install system dependencies required by agentsh
    await rawSandbox.runCommand({
      cmd: 'dnf',
      args: ['install', '-y', 'libseccomp', 'fuse3', 'fuse3-libs'],
      sudo: true,
    });

    const adapter = vercel(rawSandbox);
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
  // Note: In "minimal" security mode (common on Firecracker VMs), some
  // policy enforcement is limited. These tests verify what agentsh can
  // enforce at the seccomp/shim level.

  it('denies writing to .env file (full/landlock mode)', async () => {
    // File deny rules require FUSE or landlock for enforcement
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
    // Command interception for sub-processes requires seccomp user_notify
    if (secured.securityMode === 'full' || secured.securityMode === 'landlock') {
      const result = await secured.exec('sudo whoami');
      expect(result.exitCode).not.toBe(0);
    }
  });

  it('blocks env command (full/landlock mode)', async () => {
    if (secured.securityMode === 'full' || secured.securityMode === 'landlock') {
      const result = await secured.exec('env');
      expect(result.exitCode).not.toBe(0);
    }
  });

  it('blocks printenv command (full/landlock mode)', async () => {
    if (secured.securityMode === 'full' || secured.securityMode === 'landlock') {
      const result = await secured.exec('printenv');
      expect(result.exitCode).not.toBe(0);
    }
  });

  it('allows curl to npm registry (if curl available)', async () => {
    // curl may be redirected to agentsh-fetch, which still allows npm registry
    const result = await secured.exec(
      'curl -s -o /dev/null -w "%{http_code}" https://registry.npmjs.org/ || echo "no-curl"',
    );
    // Either succeeds with 200, or curl not available
    if (!result.stdout.includes('no-curl')) {
      expect(result.stdout.trim()).toBe('200');
    }
  });

  it('blocks network to unauthorized host', async () => {
    const result = await secured.exec(
      'curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 https://evil.example.com 2>&1',
    );
    // Should fail — either blocked by proxy (400/403) or connection refused
    expect(result.stdout.trim()).not.toBe('200');
  });

  it('filters sensitive env vars from process environment', async () => {
    const result = await secured.exec('bash -c "echo $SECRET_KEY"');
    // SECRET_KEY should not be set / should be empty
    expect(result.stdout.trim()).toBe('');
  });
});
