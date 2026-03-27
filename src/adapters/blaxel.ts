import type { SandboxAdapter, SecureConfig } from '../core/types.js';
import { shellEscape, envPrefix } from '../core/shell.js';
import { agentDefault } from '../policies/presets.js';
import { mergePrepend } from '../policies/merge.js';

export function blaxel(sandbox: any): SandboxAdapter {
  return {
    async exec(cmd, args, opts) {
      let command = `${envPrefix(opts?.env)}${shellEscape(cmd, args)}`;
      if (opts?.sudo) command = `sudo ${command}`;

      const execOpts: Record<string, unknown> = {
        command,
        waitForCompletion: !opts?.detached,
        timeout: 60,
      };
      if (opts?.cwd) execOpts.workingDir = opts.cwd;

      if (opts?.detached) {
        execOpts.command = `nohup ${command} > /dev/null 2>&1 &`;
        sandbox.process.exec(execOpts).catch(() => {});
        return { stdout: '', stderr: '', exitCode: 0 };
      }

      const result = await sandbox.process.exec(execOpts);
      return {
        stdout: result.stdout ?? '',
        stderr: result.stderr ?? '',
        exitCode: result.exitCode ?? 0,
      };
    },
    async writeFile(path, content) {
      const buf = Buffer.isBuffer(content) ? content : Buffer.from(content);
      const b64 = buf.toString('base64');
      const command = shellEscape('sh', ['-c', 'printf "%s" "$1" | base64 -d > "$2"', '_', b64, path]);
      const result = await sandbox.process.exec({
        command,
        waitForCompletion: true,
        timeout: 60,
      });
      if ((result.exitCode ?? 0) !== 0) {
        throw new Error(`writeFile failed (exit ${result.exitCode}): ${result.stderr ?? ''}`);
      }
    },
    async readFile(path) {
      const command = shellEscape('cat', [path]);
      const result = await sandbox.process.exec({
        command,
        waitForCompletion: true,
        timeout: 60,
      });
      if ((result.exitCode ?? 0) !== 0) {
        throw new Error(`readFile failed (exit ${result.exitCode}): ${result.stderr ?? ''}`);
      }
      return result.stdout ?? '';
    },
    async stop() {
      await sandbox.delete();
    },
  };
}

/**
 * Returns Blaxel-optimized defaults for SecureConfig.
 *
 * Extends agentDefault() with Blaxel-specific paths:
 * - /app/** workspace (Blaxel uses /app instead of /workspace)
 * - /root/** read access
 * - Broader /proc and /sys read access
 * - /dev/**, /run/**, /var/log/** access
 * - Broad /etc read
 */
export function blaxelDefaults(): Partial<SecureConfig> {
  const policy = mergePrepend(agentDefault(), {
    file: [
      // Blaxel workspace at /app
      { allow: ['/app', '/app/**'], ops: ['read', 'write', 'create', 'open', 'stat', 'list', 'readlink', 'mkdir', 'chmod', 'rename'] },
      { softDelete: ['/app', '/app/**'] },
      // Root home read access
      { allow: ['/root', '/root/**'], ops: ['read', 'open', 'stat', 'list', 'readlink'] },
      // Broad /etc read
      { allow: ['/etc', '/etc/**'], ops: ['read', 'open', 'stat', 'list', 'readlink'] },
      // Full /proc read (Blaxel needs process introspection)
      { allow: '/proc/**', ops: ['read', 'open', 'stat', 'list', 'readlink'] },
      // /sys read (system info)
      { allow: '/sys/**', ops: ['read', 'open', 'stat', 'list', 'readlink'] },
      // Device files — full access
      { allow: '/dev/**', ops: ['read', 'write', 'open', 'stat'] },
      // Runtime state
      { allow: '/run/**', ops: ['read', 'open', 'stat', 'list'] },
      // Log files
      { allow: '/var/log/**', ops: ['read', 'write', 'open', 'stat', 'list'] },
    ],
  });

  return { policy };
}
