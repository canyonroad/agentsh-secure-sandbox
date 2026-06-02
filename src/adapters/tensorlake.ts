import type { SandboxAdapter, SecureConfig, ExecResult } from '../core/types.js';
import { shellEscape } from '../core/shell.js';

/** Tunables for the agentsh shim env injected on every command. */
export interface TensorlakeOptions {
  /** Injected as AGENTSH_SERVER. Default 'http://127.0.0.1:18080'. */
  serverAddr?: string;
  /** Injected as HOME. Default '/home/tl-user' (tensorlake/ubuntu-systemd base). */
  home?: string;
  /**
   * Injected as PATH. Tensorlake's exec API replaces the inherited environment
   * when env= is set, so PATH must be restored or binaries are not found.
   * Default: standard Debian PATH.
   */
  path?: string;
}

const DEFAULT_SERVER_ADDR = 'http://127.0.0.1:18080';
const DEFAULT_HOME = '/home/tl-user';
const DEFAULT_PATH = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin';

/**
 * Wraps a Tensorlake sandbox into a SandboxAdapter.
 *
 * Tensorlake provides Firecracker microVM sandboxes via a Python-first SDK
 * (`tensorlake.sandbox.SandboxClient`) — there is no JS client, so `sandbox`
 * is typed `any`. The adapter expects an object shaped like the Python SDK:
 *   - `sandbox.run(cmd, args, { env, timeout? }): { stdout, stderr, exit_code }`
 *   - `sandbox.write_file(path, bytes)`        (or `writeFile`)
 *   - optional `sandbox.read_file(path)`       (or `readFile`)
 *   - optional `sandbox.terminate()` / `close()`
 *
 * Use with the prebuilt `agentsh-sandbox-*` image (agentsh baked in + started by
 * systemd + shell shim installed). Pair with `tensorlakeDefaults()`, which
 * selects `installStrategy: 'running'` (passthrough — the shim enforces policy).
 *
 * CRITICAL: Tensorlake's exec API does not source /etc/environment and replaces
 * the inherited environment when env= is passed. This adapter therefore injects
 * AGENTSH_SHIM_FORCE / AGENTSH_SERVER / PATH / HOME on EVERY command so the shim
 * always activates — without it, commands run as plain bash and policy is
 * silently not enforced (fail-open).
 *
 * @example
 * ```ts
 * import { secureSandbox } from '@agentsh/secure-sandbox';
 * import { tensorlake, tensorlakeDefaults } from '@agentsh/secure-sandbox/adapters/tensorlake';
 *
 * // `sb` is a connected Tensorlake sandbox (built from an agentsh-baked image)
 * const sandbox = await secureSandbox(tensorlake(sb), tensorlakeDefaults());
 * await sandbox.exec('echo hello');
 * ```
 */
export function tensorlake(sandbox: any, opts?: TensorlakeOptions): SandboxAdapter {
  const shimEnv: Record<string, string> = {
    AGENTSH_SHIM_FORCE: '1',
    AGENTSH_SERVER: opts?.serverAddr ?? DEFAULT_SERVER_ADDR,
    PATH: opts?.path ?? DEFAULT_PATH,
    HOME: opts?.home ?? DEFAULT_HOME,
  };

  function normalize(result: any): ExecResult {
    return {
      stdout: result?.stdout ?? '',
      stderr: result?.stderr ?? '',
      exitCode: result?.exit_code ?? result?.exitCode ?? 0,
    };
  }

  async function call(
    cmd: string,
    args: string[],
    env: Record<string, string>,
  ): Promise<ExecResult> {
    try {
      return normalize(await sandbox.run(cmd, args, { env }));
    } catch (err: any) {
      return {
        stdout: err?.stdout ?? '',
        stderr: err?.stderr ?? err?.message ?? String(err),
        exitCode: err?.exit_code ?? err?.exitCode ?? err?.code ?? 1,
      };
    }
  }

  return {
    async exec(cmd, args, opts) {
      // Note: opts.sudo is intentionally ignored. The agentsh policy denies the
      // sudo binary, and shimmed commands already run inside the agentsh root
      // session, so a `sudo` prefix is both unnecessary and policy-denied.
      const env = { ...shimEnv, ...opts?.env };

      if (opts?.detached) {
        const inner = shellEscape(cmd, args);
        // Best-effort fire-and-forget: swallow both a synchronous throw and an
        // async rejection so a detached launch never surfaces an error.
        try {
          void Promise.resolve(
            sandbox.run('bash', ['-c', `nohup ${inner} > /dev/null 2>&1 &`], { env }),
          ).catch(() => {});
        } catch {
          /* ignore */
        }
        return { stdout: '', stderr: '', exitCode: 0 };
      }

      if (opts?.cwd) {
        const inner = shellEscape(cmd, args);
        const wrapped = `cd '${opts.cwd.replace(/'/g, "'\\''")}' && ${inner}`;
        return call('bash', ['-c', wrapped], env);
      }

      // Common path: the passthrough runtime calls exec('bash', ['-c', command]),
      // which matches the Python demo's `sb.run("bash", ["-c", cmd], env=…)`.
      return call(cmd, args ?? [], env);
    },

    async writeFile(path, content) {
      const buf = Buffer.isBuffer(content) ? content : Buffer.from(content);
      const fn = sandbox.write_file ?? sandbox.writeFile;
      if (typeof fn !== 'function') {
        throw new Error('tensorlake: sandbox has no write_file/writeFile method');
      }
      await fn.call(sandbox, path, buf);
    },

    async readFile(path) {
      const fn = sandbox.read_file ?? sandbox.readFile;
      if (typeof fn === 'function') {
        const out = await fn.call(sandbox, path);
        return typeof out === 'string' ? out : Buffer.from(out).toString('utf-8');
      }
      // Tensorlake's SDK may not expose a read API — fall back to `cat`.
      const result = await call('cat', [path], shimEnv);
      if (result.exitCode !== 0) {
        throw new Error(`readFile failed (exit ${result.exitCode}): ${result.stderr}`);
      }
      return result.stdout;
    },

    async stop() {
      // Tensorlake lifecycle is normally caller-managed via the context manager
      // (`create_and_connect`). stop() is best-effort: attempt both terminate
      // and close if present, and never let a failure in one propagate.
      if (typeof sandbox.terminate === 'function') {
        try { await sandbox.terminate(); } catch { /* best-effort */ }
      }
      if (typeof sandbox.close === 'function') {
        try { await sandbox.close(); } catch { /* best-effort */ }
      }
    },

    async fileExists(path) {
      const result = await call('test', ['-f', path], shimEnv);
      return result.exitCode === 0;
    },
  };
}

/**
 * Returns Tensorlake-optimized defaults for SecureConfig.
 *
 * Key characteristics:
 * - installStrategy: 'running' — agentsh is baked into the image and started by
 *   systemd; the shell shim is installed at build time. The library does NOT
 *   download/install/start the server. provision() health-checks the running
 *   server and hands off to passthrough mode (the shim enforces policy on every
 *   `bash -c`).
 * - No `policy` / `serverConfig` are returned. The 'running' branch of
 *   provision() returns before any policy/config is written, so anything here
 *   would be inert. Policy + server config live in the baked image
 *   (config.yaml / default.yaml), built by the Python build_image.py.
 * - sessionId: 'tensorlake-shim' — cosmetic. The 'running' path requires a
 *   session ID, but the baked shim manages sessions transparently and exposes
 *   no stable ID. Passthrough runtime never uses sessionId for exec; it is
 *   surfaced only as SecuredSandbox.sessionId for telemetry.
 * - securityMode: 'full' — set explicitly so minimumSecurityMode works in the
 *   'running' strategy (where `agentsh detect` is skipped). Matches the demo's
 *   active backends (FUSE + seccomp + ptrace).
 *
 * Spread into your secureSandbox() call:
 *
 *   secureSandbox(tensorlake(sb), { ...tensorlakeDefaults(), ...yourOverrides })
 */
export function tensorlakeDefaults(): Partial<SecureConfig> {
  return {
    installStrategy: 'running',
    workspace: '/workspace',
    sessionId: 'tensorlake-shim',
    securityMode: 'full',
  };
}
