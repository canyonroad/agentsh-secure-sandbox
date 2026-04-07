# Freestyle Provider Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add freestyle.sh as a supported sandbox provider in `@agentsh/secure-sandbox` with a typed adapter, high-security defaults translated from the agentsh-freestyle reference project, and a `configureFreestyleSpec` helper that bakes agentsh into a `VmSpec`.

**Architecture:** Three public exports in `src/adapters/freestyle.ts`: (1) `freestyle(vm)` — a `SandboxAdapter` that routes `exec` through `vm.exec({command, timeoutMs})` and file ops through `vm.fs.*`; (2) `freestyleDefaults()` — a `Partial<SecureConfig>` with the deny-by-default policy and a Freestyle-tuned `serverConfig` (`allowDegraded: true`, seccomp `fileMonitor.enabled: false`, FUSE deferred with `sudo /bin/chmod 666 /dev/fuse`); (3) `configureFreestyleSpec(spec)` — a VmSpec helper that installs agentsh via systemd oneshot. The adapter uses the existing `shellEscape` / `envPrefix` helpers and follows the exact code shape of `src/adapters/runloop.ts`, differing only where Freestyle's `vm.fs.*` API lets us skip the base64-over-exec workaround.

**Tech Stack:** TypeScript (strict), Vitest, tsup, `freestyle-sandboxes` (optional peer dep), `js-yaml` (already a dep via policies/serialize), `dotenv` (for e2e).

**Reference sources** (read-only — do not modify):
- Design spec: `docs/superpowers/specs/2026-04-07-freestyle-provider-design.md`
- Primary code template: `src/adapters/runloop.ts`
- Secondary template (server config shape, policy translation, `fileExists`): `src/adapters/exe.ts`
- Policy to port: `/home/eran/work/canyonroad/agentsh-freestyle/default.yaml`
- Server config to port: `/home/eran/work/canyonroad/agentsh-freestyle/config.yaml`
- VmSpec / startup template: `/home/eran/work/canyonroad/agentsh-freestyle/src/vm-agentsh.ts` + `agentsh-startup.sh`
- E2E runner template: `src/e2e/runloop-e2e-runner.ts`
- Shell helpers: `src/core/shell.ts` (`shellEscape`, `envPrefix` — use these, don't re-implement)

**Key constants referenced across tasks:**
- `AGENTSH_VERSION = '0.17.0'` — matches `scripts/build-sandbox-images.ts:22` and the exe.dev adapter
- Agentsh gRPC endpoint (default): `127.0.0.1:9090`
- Agentsh HTTP health endpoint (when configureFreestyleSpec runs the server): `http://127.0.0.1:18080/health`
- FUSE marker file: `/tmp/.agentsh-fuse-enabled`
- Workspace: `/home/user` (Freestyle VM default home)

---

## File Structure

**Files created:**
- `src/adapters/freestyle.ts` — factory + defaults + VmSpec helper + embedded startup script
- `src/e2e/freestyle-e2e-runner.ts` — live e2e runner (parallel to `runloop-e2e-runner.ts`)
- `docs/superpowers/plans/2026-04-07-freestyle-provider.md` — this plan (already exists once you read this)

**Files modified:**
- `src/adapters/index.ts` — add three exports
- `src/adapters/adapters.test.ts` — add `freestyle adapter` describe block and extend provider-defaults matrix
- `package.json` — add `./adapters/freestyle` export, `freestyle-sandboxes` optional peer dep, `test:e2e:freestyle` script
- `README.md` — add Freestyle to platform tables and examples

---

## Task 1: Scaffold `src/adapters/freestyle.ts` with the adapter factory

**Files:**
- Create: `src/adapters/freestyle.ts`
- Test: `src/adapters/adapters.test.ts` (failing test added in Task 2, not here)

This task creates the minimum scaffolding so `freestyle(vm)` compiles and returns a `SandboxAdapter` whose methods throw "not implemented" errors. Real behavior is filled in across Tasks 2–6, each driven by its own test.

- [ ] **Step 1: Create the file skeleton with imports and factory signature**

Create `src/adapters/freestyle.ts` with:

```ts
import type { SandboxAdapter, SecureConfig } from '../core/types.js';
import type { ServerConfigOpts } from '../core/config.js';
import type { PolicyDefinition } from '../policies/schema.js';
import { shellEscape, envPrefix } from '../core/shell.js';
import { generateServerConfig } from '../core/config.js';
import { serializePolicy } from '../policies/serialize.js';

const AGENTSH_VERSION = '0.17.0';

/**
 * Wraps a Freestyle VM into a SandboxAdapter.
 *
 * Freestyle provides Firecracker-backed Linux VMs accessed via the
 * `freestyle-sandboxes` SDK. Unlike shell-only providers, Freestyle
 * exposes a typed filesystem API (`vm.fs.*`), so `writeFile`/`readFile`
 * use it directly instead of the base64-over-exec workaround.
 *
 * The `vm` parameter is typed `any` to keep `freestyle-sandboxes` as an
 * optional peer dependency. The adapter expects these methods:
 *   - `vm.exec({command, timeoutMs?}): Promise<{stdout?, stderr?, statusCode?}>`
 *   - `vm.fs.writeTextFile(path, content): Promise<void>`
 *   - `vm.fs.readTextFile(path): Promise<string>`
 *   - `vm.fs.exists(path): Promise<boolean>`
 *   - `vm.stop(): Promise<unknown>`
 *
 * Use `freestyleDefaults()` for security configuration optimized for
 * Freestyle's kernel (no Yama, so seccomp file_monitor is disabled; FUSE
 * in deferred mode with `sudo /bin/chmod 666 /dev/fuse`).
 *
 * @example
 * ```ts
 * import { freestyle as freestyleClient, VmSpec } from 'freestyle-sandboxes';
 * import { secureSandbox } from '@agentsh/secure-sandbox';
 * import { freestyle, freestyleDefaults } from '@agentsh/secure-sandbox/adapters/freestyle';
 *
 * const fs = freestyleClient({ apiKey: process.env.FREESTYLE_API_KEY });
 * const { vm } = await fs.vms.create({ spec: new VmSpec() });
 * const sandbox = await secureSandbox(freestyle(vm), freestyleDefaults());
 * await sandbox.exec('echo hello');
 * await sandbox.stop();
 * ```
 */
export function freestyle(vm: any): SandboxAdapter {
  return {
    async exec(_cmd, _args, _opts) {
      throw new Error('freestyle.exec: not implemented');
    },
    async writeFile(_path, _content) {
      throw new Error('freestyle.writeFile: not implemented');
    },
    async readFile(_path) {
      throw new Error('freestyle.readFile: not implemented');
    },
    async stop() {
      throw new Error('freestyle.stop: not implemented');
    },
    async fileExists(_path) {
      throw new Error('freestyle.fileExists: not implemented');
    },
  };
}

export function freestyleDefaults(): Partial<SecureConfig> {
  throw new Error('freestyleDefaults: not implemented');
}

export function configureFreestyleSpec(_spec: any, _opts?: { agentshVersion?: string; policyYaml?: string; configYaml?: string }): any {
  throw new Error('configureFreestyleSpec: not implemented');
}
```

- [ ] **Step 2: Run typecheck to confirm the scaffold compiles**

Run: `npm run typecheck`
Expected: PASS (no errors related to `freestyle.ts`). If errors appear, fix them before moving on.

- [ ] **Step 3: Commit**

```bash
git add src/adapters/freestyle.ts
git commit -m "feat(freestyle): scaffold adapter factory + defaults + spec helper"
```

---

## Task 2: TDD `freestyle.exec` — basic command + statusCode normalization

**Files:**
- Modify: `src/adapters/freestyle.ts`
- Test: `src/adapters/adapters.test.ts` (add new describe block after the `runloop adapter` describe ends, around line 842)

- [ ] **Step 1: Add the test file imports and freestyle describe block**

At the top of `src/adapters/adapters.test.ts`, after the `runloop` imports (around line 9), add:

```ts
import { freestyle } from './freestyle.js';
```

And after the existing imports for `*Defaults` (around line 17), add:

```ts
import { freestyleDefaults } from './freestyle.js';
```

- [ ] **Step 2: Write the failing test for exec mapping**

After the closing `});` of the `runloop adapter` describe (around line 842), and before `// ─── Provider defaults ──────────────────────────────────────`, add:

```ts
describe('freestyle adapter', () => {
  function mockVm(execResponse: { stdout?: string | null; stderr?: string | null; statusCode?: number | null } = { stdout: 'out', stderr: '', statusCode: 0 }) {
    return {
      exec: vi.fn(async (_opts: { command: string; timeoutMs?: number } | string) => execResponse),
      fs: {
        writeTextFile: vi.fn(async (_path: string, _content: string) => {}),
        writeFile: vi.fn(async (_path: string, _content: Buffer) => {}),
        readTextFile: vi.fn(async (_path: string) => 'file content'),
        exists: vi.fn(async (_path: string) => true),
      },
      stop: vi.fn(async () => ({})),
    };
  }

  it('maps exec to vm.exec with sh -c wrapper', async () => {
    const mock = mockVm();
    const adapter = freestyle(mock);
    const result = await adapter.exec('ls', ['-la']);
    expect(mock.exec).toHaveBeenCalledWith(
      expect.objectContaining({ command: expect.stringContaining('ls -la') }),
    );
    expect(result.stdout).toBe('out');
    expect(result.exitCode).toBe(0);
  });

  it('normalizes null statusCode to exitCode 0', async () => {
    const mock = mockVm({ stdout: 'ok', stderr: null, statusCode: null });
    const adapter = freestyle(mock);
    const result = await adapter.exec('true', []);
    expect(result.exitCode).toBe(0);
    expect(result.stderr).toBe('');
  });

  it('propagates non-zero statusCode', async () => {
    const mock = mockVm({ stdout: '', stderr: 'nope', statusCode: 2 });
    const adapter = freestyle(mock);
    const result = await adapter.exec('false', []);
    expect(result.exitCode).toBe(2);
    expect(result.stderr).toBe('nope');
  });
});
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `npx vitest run src/adapters/adapters.test.ts -t "freestyle adapter"`
Expected: 3 failures, all with "freestyle.exec: not implemented".

- [ ] **Step 4: Implement exec in `src/adapters/freestyle.ts`**

Replace the entire `freestyle` function body with:

```ts
export function freestyle(vm: any): SandboxAdapter {
  async function run(command: string, timeoutMs?: number): Promise<{ stdout: string; stderr: string; exitCode: number }> {
    try {
      const result = await vm.exec({ command, timeoutMs });
      return {
        stdout: result?.stdout ?? '',
        stderr: result?.stderr ?? '',
        exitCode: result?.statusCode ?? 0,
      };
    } catch (err: any) {
      return {
        stdout: err?.stdout ?? '',
        stderr: err?.stderr ?? err?.message ?? String(err),
        exitCode: err?.statusCode ?? err?.exitCode ?? 1,
      };
    }
  }

  return {
    async exec(cmd, args, opts) {
      const inner = `${envPrefix(opts?.env)}${opts?.sudo ? 'sudo ' : ''}${shellEscape(cmd, args)}`;
      const wrapped = opts?.cwd
        ? `cd '${opts.cwd.replace(/'/g, "'\\''")}' && ${inner}`
        : inner;
      const command = `sh -c ${shellEscape('', [wrapped])}`;

      if (opts?.detached) {
        run(`sh -c ${shellEscape('', [`nohup ${wrapped} > /dev/null 2>&1 &`])}`).catch(() => {});
        return { stdout: '', stderr: '', exitCode: 0 };
      }

      return run(command);
    },
    async writeFile(_path, _content) {
      throw new Error('freestyle.writeFile: not implemented');
    },
    async readFile(_path) {
      throw new Error('freestyle.readFile: not implemented');
    },
    async stop() {
      throw new Error('freestyle.stop: not implemented');
    },
    async fileExists(_path) {
      throw new Error('freestyle.fileExists: not implemented');
    },
  };
}
```

Note on the `sh -c` escape: `shellEscape('', [wrapped])` reuses the existing `quoteArg` logic inside `shellEscape` by passing an empty command and the single wrapped payload as an arg. The result is `"' <payload> '"` style quoting that safely nests the inner command. This matches how the exe.dev adapter wraps its payload and avoids re-implementing shell-escape logic.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `npx vitest run src/adapters/adapters.test.ts -t "freestyle adapter"`
Expected: 3 passes.

- [ ] **Step 6: Commit**

```bash
git add src/adapters/freestyle.ts src/adapters/adapters.test.ts
git commit -m "feat(freestyle): implement exec with sh -c wrapper and statusCode normalization"
```

---

## Task 3: TDD `freestyle.exec` — sudo / cwd / env / detached

**Files:**
- Modify: `src/adapters/freestyle.ts` (already handled in Task 2; this task adds tests to prove the existing implementation works)
- Modify: `src/adapters/adapters.test.ts`

- [ ] **Step 1: Add the failing tests for sudo, cwd, env, detached**

Inside the `describe('freestyle adapter', ...)` block you created in Task 2, add after the three existing `it` tests:

```ts
  it('prepends sudo when opts.sudo is true', async () => {
    const mock = mockVm();
    const adapter = freestyle(mock);
    await adapter.exec('chmod', ['755', '/tmp/x'], { sudo: true });
    expect(mock.exec).toHaveBeenCalledWith(
      expect.objectContaining({ command: expect.stringContaining('sudo chmod') }),
    );
  });

  it('wraps with cd when opts.cwd is set', async () => {
    const mock = mockVm();
    const adapter = freestyle(mock);
    await adapter.exec('ls', [], { cwd: '/home/user/project' });
    expect(mock.exec).toHaveBeenCalledWith(
      expect.objectContaining({ command: expect.stringContaining("cd '/home/user/project' && ls") }),
    );
  });

  it('escapes single quotes in cwd', async () => {
    const mock = mockVm();
    const adapter = freestyle(mock);
    await adapter.exec('ls', [], { cwd: "/tmp/it's-weird" });
    expect(mock.exec).toHaveBeenCalledWith(
      expect.objectContaining({ command: expect.stringContaining("cd '/tmp/it'\\''s-weird'") }),
    );
  });

  it('includes env vars as inline assignments', async () => {
    const mock = mockVm();
    const adapter = freestyle(mock);
    await adapter.exec('agentsh', ['exec'], { env: { TRACEPARENT: '00-abc-def-01' } });
    expect(mock.exec).toHaveBeenCalledWith(
      expect.objectContaining({ command: expect.stringContaining('TRACEPARENT=00-abc-def-01') }),
    );
  });

  it('detached returns immediately with exitCode 0', async () => {
    const mock = mockVm();
    const adapter = freestyle(mock);
    const result = await adapter.exec('server', ['start'], { detached: true });
    expect(result.exitCode).toBe(0);
  });

  it('surfaces SDK errors as exitCode 1 without throwing', async () => {
    const mock = mockVm();
    mock.exec.mockRejectedValueOnce(new Error('network error'));
    const adapter = freestyle(mock);
    const result = await adapter.exec('whatever', []);
    expect(result.exitCode).toBe(1);
    expect(result.stderr).toContain('network error');
  });
```

- [ ] **Step 2: Run the tests**

Run: `npx vitest run src/adapters/adapters.test.ts -t "freestyle adapter"`
Expected: All 9 freestyle adapter tests pass. (The implementation from Task 2 already handles these cases.)

If any fail, fix the implementation in `src/adapters/freestyle.ts` until they pass. Do not re-implement anything that already works.

- [ ] **Step 3: Commit**

```bash
git add src/adapters/adapters.test.ts
git commit -m "test(freestyle): cover sudo, cwd, env, detached, error paths in exec"
```

---

## Task 4: TDD `writeFile` / `readFile` / `fileExists` / `stop`

**Files:**
- Modify: `src/adapters/freestyle.ts`
- Modify: `src/adapters/adapters.test.ts`

- [ ] **Step 1: Add failing tests for the filesystem methods**

Inside the `describe('freestyle adapter', ...)` block, add after the existing tests:

```ts
  it('writeFile with string uses vm.fs.writeTextFile', async () => {
    const mock = mockVm();
    const adapter = freestyle(mock);
    await adapter.writeFile('/home/user/a.txt', 'hello');
    expect(mock.fs.writeTextFile).toHaveBeenCalledWith('/home/user/a.txt', 'hello');
    expect(mock.exec).not.toHaveBeenCalled();
  });

  it('writeFile with Buffer uses vm.fs.writeFile', async () => {
    const mock = mockVm();
    const adapter = freestyle(mock);
    const buf = Buffer.from([0, 1, 2, 3]);
    await adapter.writeFile('/home/user/a.bin', buf);
    expect(mock.fs.writeFile).toHaveBeenCalledWith('/home/user/a.bin', buf);
    expect(mock.fs.writeTextFile).not.toHaveBeenCalled();
  });

  it('writeFile wraps SDK errors', async () => {
    const mock = mockVm();
    mock.fs.writeTextFile.mockRejectedValueOnce(new Error('permission denied'));
    const adapter = freestyle(mock);
    await expect(adapter.writeFile('/root/x', 'y')).rejects.toThrow(/writeFile failed.*permission denied/);
  });

  it('readFile uses vm.fs.readTextFile', async () => {
    const mock = mockVm();
    mock.fs.readTextFile.mockResolvedValueOnce('contents');
    const adapter = freestyle(mock);
    const got = await adapter.readFile('/home/user/b.txt');
    expect(mock.fs.readTextFile).toHaveBeenCalledWith('/home/user/b.txt');
    expect(got).toBe('contents');
  });

  it('readFile wraps SDK errors', async () => {
    const mock = mockVm();
    mock.fs.readTextFile.mockRejectedValueOnce(new Error('no such file'));
    const adapter = freestyle(mock);
    await expect(adapter.readFile('/missing')).rejects.toThrow(/readFile failed.*no such file/);
  });

  it('fileExists returns vm.fs.exists result', async () => {
    const mock = mockVm();
    mock.fs.exists.mockResolvedValueOnce(true);
    const adapter = freestyle(mock);
    expect(await adapter.fileExists!('/usr/local/bin/agentsh')).toBe(true);

    mock.fs.exists.mockResolvedValueOnce(false);
    expect(await adapter.fileExists!('/nope')).toBe(false);
  });

  it('stop calls vm.stop', async () => {
    const mock = mockVm();
    const adapter = freestyle(mock);
    await adapter.stop!();
    expect(mock.stop).toHaveBeenCalled();
  });
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `npx vitest run src/adapters/adapters.test.ts -t "freestyle adapter"`
Expected: The 7 new tests fail with "not implemented" errors.

- [ ] **Step 3: Replace the stub methods in `src/adapters/freestyle.ts`**

Replace the body of the `freestyle` function's returned object (the stubs for `writeFile`, `readFile`, `stop`, `fileExists`) with:

```ts
    async writeFile(path, content) {
      try {
        if (Buffer.isBuffer(content)) {
          await vm.fs.writeFile(path, content);
        } else {
          await vm.fs.writeTextFile(path, content);
        }
      } catch (err: any) {
        throw new Error(`writeFile failed: ${err?.message ?? err}`);
      }
    },
    async readFile(path) {
      try {
        return await vm.fs.readTextFile(path);
      } catch (err: any) {
        throw new Error(`readFile failed: ${err?.message ?? err}`);
      }
    },
    async stop() {
      await vm.stop();
    },
    async fileExists(path) {
      return await vm.fs.exists(path);
    },
```

(Keep the existing `exec` method unchanged — only the four stubs are replaced.)

- [ ] **Step 4: Run the tests to verify they pass**

Run: `npx vitest run src/adapters/adapters.test.ts -t "freestyle adapter"`
Expected: All 16 freestyle adapter tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/adapters/freestyle.ts src/adapters/adapters.test.ts
git commit -m "feat(freestyle): implement writeFile/readFile/fileExists/stop via vm.fs"
```

---

## Task 5: Implement `freestyleDefaults` — server config half

**Files:**
- Modify: `src/adapters/freestyle.ts`

This task fills in `freestyleDefaults()` with the server config portion (ported from `agentsh-freestyle/config.yaml`). Task 6 adds the policy half. Both halves must exist before the provider-defaults tests can pass, so we skip direct TDD here and verify via the existing schema validation in Task 8.

- [ ] **Step 1: Replace the `freestyleDefaults` stub with the full server config + empty policy**

In `src/adapters/freestyle.ts`, replace the `freestyleDefaults` function with:

```ts
/**
 * Returns Freestyle-optimized defaults for SecureConfig.
 *
 * Key characteristics:
 * - allowDegraded: true — Freestyle kernels lack Yama, so seccomp
 *   file_monitor is disabled; agentsh settles into `minimal` security
 *   mode (seccomp wrapper + network proxy + FUSE + cgroups).
 * - FUSE deferred: enabled via `sudo /bin/chmod 666 /dev/fuse` at first
 *   session start (guarded by marker file /tmp/.agentsh-fuse-enabled).
 * - seccomp.fileMonitor disabled: conflicts with FUSE without Yama
 *   (documented in agentsh-freestyle/config.yaml).
 * - DLP with custom patterns for OpenAI / Anthropic / AWS / GitHub /
 *   JWT / Slack tokens.
 * - Workspace at /home/user (matches Freestyle VM default home).
 * - Conservative resource limits (2 GB RAM, 50% CPU, 100 PIDs).
 *
 * Spread into your secureSandbox() call:
 *
 *   secureSandbox(freestyle(vm), { ...freestyleDefaults(), ...yourOverrides })
 */
export function freestyleDefaults(): Partial<SecureConfig> {
  const serverConfig: Omit<ServerConfigOpts, 'watchtower' | 'realPaths' | 'threatFeeds' | 'packageChecks'> = {
    grpc: { addr: '127.0.0.1:9090' },
    serverTimeouts: { readTimeout: '30s', writeTimeout: '60s', maxRequestSize: '10MB' },
    logging: { level: 'info', format: 'text', output: 'stderr' },
    sessions: {
      baseDir: '/var/lib/agentsh/sessions',
      maxSessions: 100,
      defaultTimeout: '1h',
      idleTimeout: '15m',
      cleanupInterval: '5m',
    },
    audit: { enabled: true, sqlitePath: '/var/lib/agentsh/events.db' },
    sandboxLimits: { maxMemoryMb: 4096, maxCpuPercent: 100, maxProcesses: 256 },
    allowDegraded: true,
    fuse: {
      deferred: true,
      deferredMarkerFile: '/tmp/.agentsh-fuse-enabled',
      deferredEnableCommand: ['sudo', '/bin/chmod', '666', '/dev/fuse'],
    },
    networkIntercept: { interceptMode: 'all', proxyListenAddr: '127.0.0.1:0' },
    seccompDetails: {
      execve: true,
      fileMonitor: { enabled: false, enforceWithoutFuse: false },
    },
    cgroups: { enabled: true },
    unixSockets: { enabled: true },
    envInject: {
      BASH_ENV: '/usr/lib/agentsh/bash_startup.sh',
    },
    proxy: {
      mode: 'embedded',
      port: 0,
      providers: {
        anthropic: 'https://api.anthropic.com',
        openai: 'https://api.openai.com',
      },
    },
    dlp: {
      mode: 'redact',
      patterns: { email: true, phone: true, credit_card: true, ssn: true, api_keys: true },
      customPatterns: [
        { name: 'openai_key', display: 'OPENAI_KEY', regex: 'sk-[a-zA-Z0-9]{48,}' },
        { name: 'anthropic_key', display: 'ANTHROPIC_KEY', regex: 'sk-ant-[a-zA-Z0-9-]{95,}' },
        { name: 'aws_access_key', display: 'AWS_KEY', regex: 'AKIA[0-9A-Z]{16}' },
        { name: 'github_pat', display: 'GITHUB_TOKEN', regex: 'ghp_[a-zA-Z0-9]{36}' },
        { name: 'github_oauth', display: 'GITHUB_OAUTH', regex: 'gho_[a-zA-Z0-9]{36}' },
        { name: 'jwt_token', display: 'JWT', regex: 'eyJ[a-zA-Z0-9_-]*\\.eyJ[a-zA-Z0-9_-]*\\.[a-zA-Z0-9_-]*' },
        { name: 'private_key', display: 'PRIVATE_KEY', regex: '-----BEGIN [A-Z]+ PRIVATE KEY-----' },
        { name: 'slack_token', display: 'SLACK_TOKEN', regex: 'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}' },
      ],
    },
    approvals: { enabled: false },
    metrics: { enabled: true, path: '/metrics' },
    health: { path: '/health', readinessPath: '/ready' },
    development: { disableAuth: true, verboseErrors: false },
  };

  // Policy is added in Task 6.
  const policy: PolicyDefinition = {
    file: [],
    network: [],
    commands: [],
  } as unknown as PolicyDefinition;

  return {
    policy,
    workspace: '/home/user',
    installStrategy: 'download',
    realPaths: true,
    serverConfig,
  };
}
```

- [ ] **Step 2: Typecheck**

Run: `npm run typecheck`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add src/adapters/freestyle.ts
git commit -m "feat(freestyle): add serverConfig defaults (allowDegraded, deferred FUSE)"
```

---

## Task 6: Fill in the policy in `freestyleDefaults`

**Files:**
- Modify: `src/adapters/freestyle.ts`

This task ports the policy from `agentsh-freestyle/default.yaml`, converting `approve` decisions to `deny` for files/commands (which is what runloop and exe.dev do, since the TS schema only models `approve` on package rules). Read the source YAML and the `PolicyDefinition` shape in `src/adapters/exe.ts` before starting — the structure matches exactly.

- [ ] **Step 1: Replace the empty `policy` constant in `freestyleDefaults`**

In `src/adapters/freestyle.ts`, inside `freestyleDefaults()`, replace the placeholder `policy` object with:

```ts
  // Policy translated from agentsh-freestyle/default.yaml.
  // `approve` decisions on files/commands become `deny` (TS schema only
  // models `approve` for package rules, and embedded adapters have no
  // approval callback loop wired up).
  // First-match-wins: order matters.
  const policy: PolicyDefinition = {
    file: [
      // --- Deny privilege escalation binaries ---
      { deny: [
        '/usr/bin/sudo', '/usr/bin/su', '/usr/bin/pkexec', '/usr/bin/doas',
        '/bin/su', '/usr/sbin/chroot', '/usr/bin/nsenter', '/usr/bin/unshare',
      ] },

      // --- Deny Freestyle infrastructure ---
      { deny: [
        '/usr/bin/envd',
        '/usr/bin/socat',
        '/etc/systemd/**',
        '/run/systemd/**',
      ] },

      // --- Deny credentials (approve → deny) ---
      { deny: ['/home/user/.ssh/**', '/root/.ssh/**'] },
      { deny: ['/home/user/.aws/**', '/root/.aws/**'] },
      { deny: [
        '/home/user/.gcloud/**', '/home/user/.azure/**',
        '/home/user/.config/gcloud/**', '/home/user/.kube/**',
        '/root/.gcloud/**', '/root/.azure/**',
        '/root/.config/gcloud/**', '/root/.kube/**',
      ] },
      { deny: ['**/.env', '**/.env.*'] },
      { deny: ['/home/user/.git-credentials', '/root/.git-credentials', '**/.netrc'] },

      // --- Workspace: read/open/stat/list, then write/create/mkdir/chmod/rename ---
      { allow: ['/home/user', '/home/user/**', '/workspace', '/workspace/**'],
        ops: ['read', 'open', 'stat', 'list', 'readlink'] },
      { allow: ['/home/user', '/home/user/**', '/workspace', '/workspace/**'],
        ops: ['write', 'create', 'mkdir', 'chmod', 'rename'] },
      { softDelete: ['/home/user', '/home/user/**', '/workspace', '/workspace/**'] },

      // --- Temp directories (full access) ---
      { allow: ['/tmp/**', '/var/tmp/**'] },

      // --- System paths (read-only) ---
      { allow: ['/usr/**', '/lib/**', '/lib64/**', '/bin/**', '/sbin/**'],
        ops: ['read', 'open', 'stat', 'list', 'readlink'] },

      // --- Essential device nodes ---
      { allow: [
        '/dev/null', '/dev/zero', '/dev/urandom', '/dev/random',
        '/dev/stdin', '/dev/stdout', '/dev/stderr',
        '/dev/fd/**', '/dev/pts/**', '/dev/tty',
      ], ops: ['read', 'write', 'open', 'stat'] },

      // --- Package caches (read-only) ---
      { allow: [
        '/home/user/.npm/**', '/home/user/.cache/**', '/home/user/.cargo/**',
        '/root/.npm/**', '/root/.cache/**', '/root/.cargo/**',
      ], ops: ['read', 'open', 'stat', 'list'] },

      // --- Sensitive /etc files (deny before /etc read allow) ---
      { deny: ['/etc/shadow', '/etc/gshadow', '/etc/sudoers', '/etc/sudoers.d/**'] },

      // --- /etc minimal read ---
      { allow: [
        '/etc/hosts', '/etc/resolv.conf',
        '/etc/ssl/**', '/etc/ca-certificates/**',
        '/etc/localtime', '/etc/timezone',
        '/etc/ld.so.cache', '/etc/ld.so.preload', '/etc/ld.so.nohwcap',
        '/etc/nsswitch.conf', '/etc/passwd', '/etc/group',
        '/etc/fuse.conf',
      ], ops: ['read', 'open', 'stat', 'readlink'] },

      // --- /proc/self for process introspection ---
      { allow: ['/proc/self/**', '/proc/thread-self/**'],
        ops: ['read', 'open', 'stat', 'list', 'readlink'] },

      // --- agentsh runtime ---
      { allow: ['/var/lib/agentsh/**', '/var/log/agentsh/**'],
        ops: ['read', 'write', 'open', 'stat', 'list', 'readlink'] },

      // --- Block /proc and /sys (catch-all, before default deny) ---
      { deny: ['/proc/**', '/sys/**'] },

      // --- Default deny ---
      { deny: '**' },
    ],
    network: [
      // Localhost (agentsh server + embedded LLM proxy)
      { allowCidrs: ['127.0.0.1/32', '::1/128'] },
      // Package registries
      { allow: ['registry.npmjs.org'], ports: [443] },
      { allow: ['pypi.org', 'files.pythonhosted.org'], ports: [443] },
      { allow: ['crates.io', 'static.crates.io'], ports: [443] },
      { allow: ['proxy.golang.org', 'sum.golang.org'], ports: [443] },
      // Block cloud metadata (SSRF protection)
      { denyCidrs: ['169.254.169.254/32', '100.100.100.200/32'] },
      // Block private/internal networks
      { denyCidrs: ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '169.254.0.0/16'] },
      // Block Freestyle internal events service (TEST-NET-1 range per reference config)
      { denyCidrs: ['192.0.2.0/24'] },
      // Block example malicious domains (kept from reference as test fixture)
      { deny: ['evil.com', '*.evil.com'] },
      // Default deny
      { deny: '*' },
    ],
    commands: [
      // Network tools (network rules enforce domain policy)
      { allow: ['curl', 'wget'] },
      // Safe commands
      {
        allow: [
          'bash', 'sh', '/bin/bash', '/bin/sh', '/usr/bin/bash', '/usr/bin/sh',
          'ls', 'cat', 'head', 'tail', 'grep', 'find', 'wc', 'sort', 'uniq',
          'diff', 'pwd', 'echo', 'date', 'which',
          'env', 'printenv', 'true', 'false', 'test', '[',
          'expr', 'seq', 'sh.real', 'bash.real',
        ],
      },
      // Dev tools
      {
        allow: [
          'git', 'node', 'npm', 'python', 'python3', 'pip', 'pip3',
          'cargo', 'go', 'make',
        ],
      },
      // Deny raw network tools (reverse-shell prevention)
      { deny: ['nc', 'netcat', 'ncat', 'socat', 'telnet', 'ssh', 'scp', 'rsync'] },
      // Deny system administration
      {
        deny: [
          'shutdown', 'reboot', 'systemctl', 'service',
          'mount', 'umount', 'dd', 'fdisk', 'mkfs',
          'kill', 'killall', 'pkill',
        ],
      },
      // Deny privilege escalation
      { deny: ['sudo', 'su', 'doas', 'chroot', 'nsenter', 'unshare'] },
      // Deny Freestyle infrastructure interference
      { deny: ['socat', 'envd', 'iptables', 'ip6tables', 'nft', 'tc', 'ip'] },
      // Allow all other (file + network rules are the real enforcement)
      { allow: '*' },
    ],
    envPolicy: {
      allow: [
        'PATH', 'HOME', 'USER', 'SHELL', 'LANG', 'LANG_*', 'LC_*',
        'TERM', 'TERM_*', 'TZ', 'PWD', 'OLDPWD', 'SHLVL', '_',
        'NODE_ENV', 'NODE_PATH', 'NPM_*',
        'PYTHONPATH', 'VIRTUAL_ENV', 'PIP_*',
        'GIT_*',
        'AGENTSH_*',
        'HTTP_PROXY', 'HTTPS_PROXY', 'http_proxy', 'https_proxy', 'NO_PROXY', 'no_proxy',
      ],
      deny: [
        'AWS_*', 'AZURE_*', 'GCP_*', 'GOOGLE_*',
        'OPENAI_API_KEY', 'ANTHROPIC_API_KEY',
        'DATABASE_URL', 'DB_*',
        'SECRET_*', 'PASSWORD*', 'PRIVATE_*', 'API_KEY*', 'TOKEN*',
      ],
      blockIteration: true,
      maxBytes: 65536,
      maxKeys: 100,
    },
    signalRules: [
      { name: 'allow-self', signals: ['@all'], target: { type: 'self' }, decision: 'allow' },
      { name: 'allow-children', signals: ['@all'], target: { type: 'children' }, decision: 'allow' },
      { name: 'allow-session', signals: ['SIGTERM', 'SIGINT', 'SIGHUP', 'SIGUSR1', 'SIGUSR2'], target: { type: 'session' }, decision: 'allow' },
      { name: 'audit-parent', signals: ['@all'], target: { type: 'parent' }, decision: 'audit' },
      { name: 'deny-external-fatal', signals: ['@fatal'], target: { type: 'external' }, decision: 'deny', fallback: 'audit', message: 'Blocking signal to process outside session' },
      { name: 'deny-system', signals: ['@all'], target: { type: 'system' }, decision: 'deny', fallback: 'audit', message: 'Blocking signal to system process' },
    ],
    unixSocketRules: [
      { name: 'deny-system-sockets', paths: ['/var/run/**'], operations: ['connect', 'bind', 'listen', 'sendto'], decision: 'deny' },
    ],
    resourceLimits: {
      maxMemoryMb: 2048,
      cpuQuotaPercent: 50,
      pidsMax: 100,
      commandTimeout: '5m',
      sessionTimeout: '1h',
      idleTimeout: '15m',
    },
    auditSettings: {
      logAllowed: true,
      logDenied: true,
      logApproved: true,
      includeStdout: true,
      includeStderr: true,
    },
  };
```

Delete the old placeholder lines that previously set `policy` to `{ file: [], network: [], commands: [] }` and the `as unknown as PolicyDefinition` cast.

- [ ] **Step 2: Typecheck**

Run: `npm run typecheck`
Expected: PASS. If TypeScript complains about missing required fields on `PolicyDefinition`, compare against `exe.ts`'s policy object to see what's missing.

- [ ] **Step 3: Commit**

```bash
git add src/adapters/freestyle.ts
git commit -m "feat(freestyle): port policy from agentsh-freestyle default.yaml"
```

---

## Task 7: Wire `freestyleDefaults` into the provider-defaults test matrix

**Files:**
- Modify: `src/adapters/adapters.test.ts`

- [ ] **Step 1: Add freestyleDefaults to the provider matrix**

In `src/adapters/adapters.test.ts`, find the `providers` array inside `describe('provider defaults', ...)` (around line 847) and add `freestyleDefaults` as a new entry:

```ts
  const providers = [
    { name: 'vercelDefaults', fn: vercelDefaults },
    { name: 'e2bDefaults', fn: e2bDefaults },
    { name: 'daytonaDefaults', fn: daytonaDefaults },
    { name: 'cloudflareDefaults', fn: cloudflareDefaults },
    { name: 'blaxelDefaults', fn: blaxelDefaults },
    { name: 'modalDefaults', fn: modalDefaults },
    { name: 'spritesDefaults', fn: spritesDefaults },
    { name: 'runloopDefaults', fn: runloopDefaults },
    { name: 'freestyleDefaults', fn: freestyleDefaults },
  ];
```

- [ ] **Step 2: Add freestyle-specific assertion tests**

After the existing `runloopDefaults blocks raw network tools` test (search for it in the file — it's near the end of the `provider defaults` describe block), add these three tests (still inside the `provider defaults` describe):

```ts
  it('freestyleDefaults includes /home/user workspace paths', () => {
    const { policy } = freestyleDefaults() as any;
    const allPaths = policy.file
      .filter((r: any) => 'allow' in r)
      .flatMap((r: any) => Array.isArray(r.allow) ? r.allow : [r.allow]);
    expect(allPaths).toContain('/home/user/**');
    expect(allPaths).toContain('/workspace/**');
  });

  it('freestyleDefaults blocks Freestyle infrastructure', () => {
    const { policy } = freestyleDefaults() as any;
    const denyPaths = policy.file
      .filter((r: any) => 'deny' in r)
      .flatMap((r: any) => Array.isArray(r.deny) ? r.deny : [r.deny]);
    expect(denyPaths).toContain('/usr/bin/envd');
    expect(denyPaths).toContain('/usr/bin/socat');
    expect(denyPaths).toContain('/etc/systemd/**');
  });

  it('freestyleDefaults uses allowDegraded and disables seccomp file_monitor', () => {
    const defaults = freestyleDefaults() as any;
    expect(defaults.serverConfig.allowDegraded).toBe(true);
    expect(defaults.serverConfig.seccompDetails.fileMonitor.enabled).toBe(false);
    expect(defaults.serverConfig.fuse.deferred).toBe(true);
    expect(defaults.serverConfig.fuse.deferredEnableCommand).toEqual(['sudo', '/bin/chmod', '666', '/dev/fuse']);
    expect(defaults.workspace).toBe('/home/user');
  });
```

- [ ] **Step 3: Run the test suite**

Run: `npx vitest run src/adapters/adapters.test.ts`
Expected: All adapter tests pass, including the three new freestyle-specific ones and the three schema/YAML tests contributed by the provider-defaults matrix.

- [ ] **Step 4: Commit**

```bash
git add src/adapters/adapters.test.ts
git commit -m "test(freestyle): add defaults to provider matrix + specific assertions"
```

---

## Task 8: Implement `configureFreestyleSpec` helper

**Files:**
- Modify: `src/adapters/freestyle.ts`
- Modify: `src/adapters/adapters.test.ts`

The helper mutates an incoming `VmSpec` via its fluent builders. Since `VmSpec` is typed `any` (optional peer dep), we can't rely on TypeScript to catch misuse — we'll test by passing a mock with the same shape as `VmSpec` and asserting the right builder methods were called.

- [ ] **Step 1: Add the embedded install script and startup script as module-level constants**

In `src/adapters/freestyle.ts`, immediately after the `AGENTSH_VERSION` constant near the top of the file, add:

```ts
const INSTALL_SCRIPT = [
  '#!/bin/bash',
  'set -eux',
  `AGENTSH_VERSION="${AGENTSH_VERSION}"`,
  'URL="https://github.com/canyonroad/agentsh/releases/download/v${AGENTSH_VERSION}/agentsh_${AGENTSH_VERSION}_linux_amd64.tar.gz"',
  'curl -fsSL "${URL}" -o /tmp/agentsh.tar.gz',
  'tar xz -C /tmp/ -f /tmp/agentsh.tar.gz',
  'install -m 0755 /tmp/agentsh /usr/local/bin/agentsh',
  'install -m 0755 /tmp/agentsh-shell-shim /usr/bin/agentsh-shell-shim',
  'install -m 0755 /tmp/agentsh-unixwrap /usr/local/bin/agentsh-unixwrap',
  'rm -f /tmp/agentsh.tar.gz /tmp/agentsh /tmp/agentsh-shell-shim /tmp/agentsh-unixwrap',
  'mkdir -p /etc/agentsh/policies /var/lib/agentsh/quarantine /var/lib/agentsh/sessions /var/log/agentsh /home/user',
  'chmod 755 /etc/agentsh /etc/agentsh/policies /var/lib/agentsh /var/lib/agentsh/quarantine /var/lib/agentsh/sessions /var/log/agentsh',
  'echo "root ALL=(ALL) NOPASSWD: /usr/local/bin/agentsh" >> /etc/sudoers',
  'echo "root ALL=(ALL) NOPASSWD: /bin/chmod 666 /dev/fuse" >> /etc/sudoers',
  'echo "root ALL=(ALL) NOPASSWD: /bin/chmod 600 /dev/fuse" >> /etc/sudoers',
  'echo "root ALL=(ALL) NOPASSWD: /bin/mknod /dev/fuse c 10 229" >> /etc/sudoers',
  'echo "user_allow_other" >> /etc/fuse.conf',
  '/usr/local/bin/agentsh --version',
].join('\n');

const STARTUP_SCRIPT = [
  '#!/bin/bash',
  '# Restrict /dev/fuse to prevent any FUSE mount during snapshot',
  'sudo /bin/chmod 600 /dev/fuse 2>/dev/null || true',
  '',
  '# Start agentsh server in background (deferred FUSE: mounts on first exec)',
  '/usr/local/bin/agentsh server >> /var/log/agentsh/server.log 2>&1 &',
  'SERVER_PID=$!',
  '',
  '# Wait for server to be ready (health check loop)',
  'for i in $(seq 1 15); do',
  '  if curl -sf http://127.0.0.1:18080/health >/dev/null 2>&1; then break; fi',
  '  sleep 1',
  'done',
  '',
  '# Install shell shim (replaces /bin/bash with agentsh shim)',
  'sudo /usr/local/bin/agentsh shim install-shell --root / --shim /usr/bin/agentsh-shell-shim --bash --i-understand-this-modifies-the-host',
  '',
  '# Warm up the shim',
  '/bin/bash -c "echo shim warmup ok" 2>/dev/null || true',
  '',
  'echo "agentsh ready"',
  '',
  '# Keep the script alive so systemd does not kill the service cgroup',
  'wait $SERVER_PID',
].join('\n');
```

- [ ] **Step 2: Replace the `configureFreestyleSpec` stub**

Replace the entire `configureFreestyleSpec` function with:

```ts
/**
 * Bake agentsh into a Freestyle VmSpec via two systemd services: an
 * oneshot installer and the agentsh server. Call this on a fresh VmSpec
 * (usually `new VmSpec().snapshot()`) before passing it to `fs.vms.create`.
 *
 * The spec defaults the policy + server config to `freestyleDefaults()`.
 * Override either via `opts.policyYaml` or `opts.configYaml` with a
 * pre-serialized YAML string (use `serializePolicy` and
 * `generateServerConfig` from the library's internals).
 *
 * `spec` is typed `any` so callers can import `VmSpec` from
 * `freestyle-sandboxes` without making it a hard dependency.
 *
 * @example
 * ```ts
 * import { freestyle as freestyleClient, VmSpec } from 'freestyle-sandboxes';
 * import { configureFreestyleSpec, freestyle, freestyleDefaults } from '@agentsh/secure-sandbox/adapters/freestyle';
 *
 * const fs = freestyleClient({ apiKey: process.env.FREESTYLE_API_KEY });
 * const spec = configureFreestyleSpec(new VmSpec().snapshot());
 * const { vm } = await fs.vms.create({ spec });
 * const sandbox = await secureSandbox(freestyle(vm), {
 *   ...freestyleDefaults(),
 *   installStrategy: 'preinstalled',
 * });
 * ```
 */
export function configureFreestyleSpec(
  spec: any,
  opts?: { agentshVersion?: string; policyYaml?: string; configYaml?: string },
): any {
  const defaults = freestyleDefaults();
  const policyYaml = opts?.policyYaml
    ?? serializePolicy(defaults.policy as PolicyDefinition);
  const configYaml = opts?.configYaml
    ?? generateServerConfig(defaults.serverConfig as ServerConfigOpts);

  const installScript = opts?.agentshVersion
    ? INSTALL_SCRIPT.replace(`AGENTSH_VERSION="${AGENTSH_VERSION}"`, `AGENTSH_VERSION="${opts.agentshVersion}"`)
    : INSTALL_SCRIPT;

  return spec
    .aptDeps('ca-certificates', 'curl', 'jq', 'libseccomp2', 'sudo', 'fuse3', 'python3', 'file', 'sqlite3')
    .additionalFiles({
      '/opt/install-agentsh.sh': { content: installScript },
      '/etc/agentsh/config.yml': { content: configYaml },
      '/etc/agentsh/policies/default.yaml': { content: policyYaml },
      '/opt/agentsh-startup.sh': { content: STARTUP_SCRIPT },
      '/etc/environment': {
        content: [
          'AGENTSH_SERVER=http://127.0.0.1:18080',
          'AGENTSH_SHIM_FORCE=1',
        ].join('\n'),
      },
    })
    .systemdService({
      name: 'install-agentsh',
      mode: 'oneshot',
      exec: ['bash /opt/install-agentsh.sh'],
      wantedBy: ['multi-user.target'],
    })
    .systemdService({
      name: 'agentsh',
      mode: 'service',
      exec: ['bash /opt/agentsh-startup.sh'],
      env: {
        AGENTSH_SERVER: 'http://127.0.0.1:18080',
        AGENTSH_SHIM_FORCE: '1',
      },
      after: ['install-agentsh.service'],
      wantedBy: ['multi-user.target'],
    });
}
```

- [ ] **Step 3: Add a unit test for `configureFreestyleSpec`**

In `src/adapters/adapters.test.ts`, near the top of the file where `freestyle` is imported, extend the import line:

```ts
import { freestyle, configureFreestyleSpec } from './freestyle.js';
```

Then, inside `describe('freestyle adapter', ...)` — at the very end, after the last `it` — add:

```ts
  describe('configureFreestyleSpec', () => {
    function mockSpec() {
      const calls: { method: string; args: any[] }[] = [];
      const spec: any = {
        aptDeps: vi.fn((...deps: string[]) => { calls.push({ method: 'aptDeps', args: deps }); return spec; }),
        additionalFiles: vi.fn((files: any) => { calls.push({ method: 'additionalFiles', args: [files] }); return spec; }),
        systemdService: vi.fn((service: any) => { calls.push({ method: 'systemdService', args: [service] }); return spec; }),
        _calls: calls,
      };
      return spec;
    }

    it('chains builder methods on the spec', () => {
      const spec = mockSpec();
      const result = configureFreestyleSpec(spec);
      expect(result).toBe(spec);
      expect(spec.aptDeps).toHaveBeenCalledWith(
        'ca-certificates', 'curl', 'jq', 'libseccomp2', 'sudo',
        'fuse3', 'python3', 'file', 'sqlite3',
      );
    });

    it('adds install + startup scripts and serialized config/policy files', () => {
      const spec = mockSpec();
      configureFreestyleSpec(spec);
      const filesCall = spec._calls.find((c: any) => c.method === 'additionalFiles');
      const files = filesCall!.args[0];
      expect(files['/opt/install-agentsh.sh'].content).toContain('agentsh_0.17.0_linux_amd64.tar.gz');
      expect(files['/opt/agentsh-startup.sh'].content).toContain('agentsh server');
      expect(files['/etc/agentsh/config.yml'].content).toBeDefined();
      expect(files['/etc/agentsh/policies/default.yaml'].content).toContain('/home/user');
      expect(files['/etc/environment'].content).toContain('AGENTSH_SERVER=http://127.0.0.1:18080');
    });

    it('creates two systemd services with correct ordering', () => {
      const spec = mockSpec();
      configureFreestyleSpec(spec);
      const services = spec._calls.filter((c: any) => c.method === 'systemdService').map((c: any) => c.args[0]);
      expect(services).toHaveLength(2);
      expect(services[0].name).toBe('install-agentsh');
      expect(services[0].mode).toBe('oneshot');
      expect(services[1].name).toBe('agentsh');
      expect(services[1].mode).toBe('service');
      expect(services[1].after).toEqual(['install-agentsh.service']);
    });

    it('respects opts.agentshVersion override', () => {
      const spec = mockSpec();
      configureFreestyleSpec(spec, { agentshVersion: '0.99.0' });
      const filesCall = spec._calls.find((c: any) => c.method === 'additionalFiles');
      const installScript = filesCall!.args[0]['/opt/install-agentsh.sh'].content;
      expect(installScript).toContain('AGENTSH_VERSION="0.99.0"');
    });

    it('respects opts.policyYaml and opts.configYaml overrides', () => {
      const spec = mockSpec();
      configureFreestyleSpec(spec, {
        policyYaml: '# custom policy\n',
        configYaml: '# custom config\n',
      });
      const filesCall = spec._calls.find((c: any) => c.method === 'additionalFiles');
      const files = filesCall!.args[0];
      expect(files['/etc/agentsh/policies/default.yaml'].content).toBe('# custom policy\n');
      expect(files['/etc/agentsh/config.yml'].content).toBe('# custom config\n');
    });
  });
```

- [ ] **Step 4: Run the tests**

Run: `npx vitest run src/adapters/adapters.test.ts -t "freestyle"`
Expected: All freestyle adapter tests (including the 5 new `configureFreestyleSpec` tests) pass.

- [ ] **Step 5: Commit**

```bash
git add src/adapters/freestyle.ts src/adapters/adapters.test.ts
git commit -m "feat(freestyle): add configureFreestyleSpec helper with systemd install"
```

---

## Task 9: Wire exports in `src/adapters/index.ts` and `package.json`

**Files:**
- Modify: `src/adapters/index.ts`
- Modify: `package.json`

- [ ] **Step 1: Add the export line to the adapter barrel**

In `src/adapters/index.ts`, append:

```ts
export { freestyle, freestyleDefaults, configureFreestyleSpec } from './freestyle.js';
```

The complete file should now look like:

```ts
export { vercel, vercelDefaults } from './vercel.js';
export { e2b, e2bDefaults } from './e2b.js';
export { daytona, daytonaDefaults } from './daytona.js';
export { cloudflare, cloudflareDefaults } from './cloudflare.js';
export { blaxel, blaxelDefaults } from './blaxel.js';
export { sprites, spritesDefaults } from './sprites.js';
export { modal, modalDefaults } from './modal.js';
export { runloop, runloopDefaults } from './runloop.js';
export { exe, exeDefaults } from './exe.js';
export { freestyle, freestyleDefaults, configureFreestyleSpec } from './freestyle.js';
```

- [ ] **Step 2: Add the subpath export to `package.json`**

In `package.json`, inside the `exports` object, after the existing `"./adapters/exe"` entry (around line 55), add:

```json
    "./adapters/freestyle": {
      "types": "./dist/adapters/freestyle.d.ts",
      "import": "./dist/adapters/freestyle.js"
    },
```

Make sure you preserve the trailing comma on the previous entry and don't introduce trailing commas that JSON doesn't allow.

- [ ] **Step 3: Add `freestyle-sandboxes` as an optional peer dep**

In `package.json`, inside `peerDependencies`, add:

```json
    "freestyle-sandboxes": "^0.0.1"
```

And inside `peerDependenciesMeta`, add:

```json
    "freestyle-sandboxes": {
      "optional": true
    },
```

(Use whatever version is currently in `agentsh-freestyle/package.json` — check `/home/eran/work/canyonroad/agentsh-freestyle/package.json` to confirm. If the version looks pre-1.0, `^0.x.y` is the right constraint.)

- [ ] **Step 4: Add the `test:e2e:freestyle` script**

In `package.json`, inside `scripts`, add after `"test:e2e:exe"`:

```json
    "test:e2e:freestyle": "npx tsx src/e2e/freestyle-e2e-runner.ts",
```

- [ ] **Step 5: Install the dev dependency so types resolve and e2e can import it**

Also add `"freestyle-sandboxes": "^<version>"` to `devDependencies` (same version as the peer dep), so `npm install` fetches it locally and tsup/typecheck don't choke.

Then run: `npm install`
Expected: Clean install with the new package added.

- [ ] **Step 6: Run typecheck + test suite**

Run: `npm run typecheck && npx vitest run`
Expected: Both pass. No missing-export or missing-type errors.

- [ ] **Step 7: Commit**

```bash
git add src/adapters/index.ts package.json package-lock.json
git commit -m "feat(freestyle): wire exports and optional peer dep"
```

---

## Task 10: Create the E2E runner

**Files:**
- Create: `src/e2e/freestyle-e2e-runner.ts`

Mirror `src/e2e/runloop-e2e-runner.ts` — same harness, same test structure, but create a VM via `configureFreestyleSpec(new VmSpec().snapshot())` and run at `installStrategy: 'preinstalled'`.

- [ ] **Step 1: Create the runner**

Create `src/e2e/freestyle-e2e-runner.ts` with:

```ts
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
const fsClient = (fsMod as any).freestyle({ apiKey: FREESTYLE_API_KEY });
const VmSpec = (fsMod as any).VmSpec;

console.log('  → creating Freestyle VM with agentsh baked in...');

const spec = configureFreestyleSpec(new VmSpec().snapshot());
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

  await test('denies writing to /home/user/.env', async () => {
    const result = await secured!.writeFile('/home/user/.env', 'SECRET=leaked');
    assert(!result.success, 'expected .env write to be blocked');
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
```

- [ ] **Step 2: Typecheck**

Run: `npm run typecheck`
Expected: PASS. If there are missing-export errors from `freestyle-sandboxes`, that package probably doesn't export `freestyle` or `VmSpec` at the top level the way this runner expects — read `node_modules/freestyle-sandboxes/index.d.mts` (line numbers around 12352–12527 list `Vm`, `VmSpec`, and the top-level `freestyle` function) to confirm the correct import path and fix accordingly. Do **not** change the runner to import from a deep path; use whatever the package's public entry point exposes.

- [ ] **Step 3: Commit**

```bash
git add src/e2e/freestyle-e2e-runner.ts
git commit -m "test(freestyle): add E2E runner with preinstalled agentsh"
```

---

## Task 11: Update README

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Add Freestyle to the intro paragraph**

In `README.md:3`, the intro paragraph lists the supported providers. Edit it to insert `, [Freestyle](https://freestyle.sh)` between `[exe.dev](https://exe.dev)` and the closing period. The exact edit:

**Find:**
```
..., [Runloop](https://runloop.ai), and [exe.dev](https://exe.dev). Powered by [agentsh](https://www.agentsh.org).
```

**Replace with:**
```
..., [Runloop](https://runloop.ai), [exe.dev](https://exe.dev), and [Freestyle](https://freestyle.sh). Powered by [agentsh](https://www.agentsh.org).
```

- [ ] **Step 2: Add a Freestyle column to the protection matrix**

In the protection matrix (around `README.md:113`), extend the header and all six rows with a `Freestyle` column. Every row should have ✅ since the protections are the same — Freestyle's degraded mode still enforces file access (via FUSE), network filtering, command mediation, secret filtering, threat intel, and DLP.

**Find the header:**
```
| Protection | Vercel | E2B | Daytona | Cloudflare | Blaxel | Sprites | Modal | Runloop | exe.dev |
|------------|--------|-----|---------|------------|--------|---------|-------|---------|---------|
```

**Replace with:**
```
| Protection | Vercel | E2B | Daytona | Cloudflare | Blaxel | Sprites | Modal | Runloop | exe.dev | Freestyle |
|------------|--------|-----|---------|------------|--------|---------|-------|---------|---------|-----------|
```

Then, for each of the six rows below (`**File access control**` through `**DLP**`), append ` ✅ |` to the end of the row. For example:

**Find:**
```
| **File access control** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
```

**Replace with:**
```
| **File access control** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
```

Do the same for the other five rows (Network filtering, Command mediation, Secret filtering, Threat intelligence, DLP).

- [ ] **Step 3: Add Freestyle to the primary enforcement table**

In the primary enforcement table (around `README.md:124`), add a new row after the `exe.dev` row.

**Find:**
```
| [**exe.dev**](https://exe.dev) | ptrace + seccomp + Landlock + FUSE + cgroups + network proxy | `full` |
```

**Add this row directly after it:**
```
| [**Freestyle**](https://freestyle.sh) | seccomp (per-command wrapper) + network proxy + FUSE (deferred) + cgroups | `minimal` |
```

- [ ] **Step 4: Add a Freestyle callout below the existing provider callouts**

After the existing `> **exe.dev:** ...` callout (around `README.md:140`), add a new line-broken callout:

```markdown
>
> **Freestyle:** The Freestyle kernel lacks Yama, so agentsh's seccomp file_monitor is disabled (it conflicts with FUSE without Yama). FUSE runs in deferred mode with `sudo /bin/chmod 666 /dev/fuse` at first session start. Security mode settles into `minimal` — enforcement comes from the per-command seccomp wrapper, the embedded network/DLP proxy, FUSE soft-delete, and cgroups. Bake agentsh into the VM at spec time via `configureFreestyleSpec` for faster cold boots.
```

- [ ] **Step 5: Add the Freestyle usage snippet**

Inside the big `typescript` code block starting around `README.md:142`, after the `exe.dev` example block (the one ending with `});` after `...exeDefaults()`), append:

```typescript

// Freestyle (Firecracker VMs with declarative VmSpec — agentsh baked in at snapshot time)
import { freestyle as freestyleClient, VmSpec } from 'freestyle-sandboxes';
import { freestyle, freestyleDefaults, configureFreestyleSpec } from '@agentsh/secure-sandbox/adapters/freestyle';
const fs = freestyleClient({ apiKey: process.env.FREESTYLE_API_KEY });
const { vm } = await fs.vms.create({ spec: configureFreestyleSpec(new VmSpec().snapshot()) });
const sandbox = await secureSandbox(freestyle(vm), {
  ...freestyleDefaults(),
  installStrategy: 'preinstalled',
});
```

- [ ] **Step 6: Commit**

```bash
git add README.md
git commit -m "docs(freestyle): add to platforms table and usage examples"
```

---

## Task 12: Final typecheck + test run

**Files:** (no file changes, just verification)

- [ ] **Step 1: Run typecheck**

Run: `npm run typecheck`
Expected: PASS with zero errors.

- [ ] **Step 2: Run the full test suite**

Run: `npx vitest run`
Expected: PASS. The freestyle-specific test count should include:
- 16 tests in `freestyle adapter` describe (exec variants + fs methods)
- 5 tests in `configureFreestyleSpec` nested describe
- 3 tests auto-generated by the provider-defaults matrix (exists, schema, YAML)
- 3 freestyle-specific `provider defaults` assertion tests

- [ ] **Step 3: Run the build to confirm tsup emits the new adapter**

Run: `npm run build`
Expected: PASS. Confirm these files exist after build:

```
dist/adapters/freestyle.js
dist/adapters/freestyle.d.ts
```

If tsup needs a new entry in its config to pick up the new adapter, check `tsup.config.ts` — for the other per-adapter subpath exports, look at how `exe.ts` is wired and mirror it. If `tsup.config.ts` uses a glob (`src/adapters/*.ts`), no change is needed.

- [ ] **Step 4: If everything passed, commit any incidental changes**

If typecheck/test/build made no file changes, skip this. Otherwise:

```bash
git add -A
git commit -m "chore(freestyle): tsup config or minor fixups from typecheck pass"
```

- [ ] **Step 5: Final status check**

Run: `git log --oneline -15`
Expected: You should see roughly 11–12 freestyle-related commits on `main` (or a feature branch if you're in a worktree) covering scaffold → exec → fs methods → server config → policy → provider matrix → configureFreestyleSpec → exports → e2e → README → final verification.

---

## Self-Review Checklist (done — for traceability)

**Spec coverage:**
- Adapter factory (`freestyle(vm)`) → Tasks 1–4
- `freestyleDefaults()` (server config + policy) → Tasks 5–6
- Provider-defaults test matrix wiring → Task 7
- `configureFreestyleSpec` VmSpec helper → Task 8
- Barrel export + package.json export + peer dep + script → Task 9
- E2E runner → Task 10
- README updates (intro, protection matrix, enforcement table, callout, usage snippet) → Task 11
- Typecheck + tests + build verification → Task 12

**Placeholder scan:** Every code block shows exact content. The only softness is in Task 9 Step 3 where the freestyle-sandboxes version needs to be read from the reference project's `package.json` at implementation time, and Task 12 Step 3 where tsup config may or may not need editing depending on whether it uses a glob — both are clearly flagged with the lookup command.

**Type consistency:** Function names (`freestyle`, `freestyleDefaults`, `configureFreestyleSpec`), constant names (`AGENTSH_VERSION`, `INSTALL_SCRIPT`, `STARTUP_SCRIPT`), and method names (`exec`, `writeFile`, `readFile`, `fileExists`, `stop`, `fs.writeTextFile`, `fs.readTextFile`, `fs.exists`, `vm.stop`, `vm.exec`) are consistent across all tasks.
