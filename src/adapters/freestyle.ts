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
        const detached = `nohup sh -c ${shellEscape('', [wrapped])} > /dev/null 2>&1 &`;
        run(`sh -c ${shellEscape('', [detached])}`).catch(() => {});
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

export function freestyleDefaults(): Partial<SecureConfig> {
  throw new Error('freestyleDefaults: not implemented');
}

export function configureFreestyleSpec(_spec: any, _opts?: { agentshVersion?: string; policyYaml?: string; configYaml?: string }): any {
  throw new Error('configureFreestyleSpec: not implemented');
}
