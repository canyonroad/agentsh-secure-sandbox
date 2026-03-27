import type { SandboxAdapter, SecureConfig } from '../core/types.js';
import { shellEscape, envPrefix } from '../core/shell.js';
import { agentDefault } from '../policies/presets.js';
import { mergePrepend } from '../policies/merge.js';

let stderrCounter = 0;

export function daytona(sandbox: any): SandboxAdapter {
  return {
    async exec(cmd, args, opts) {
      const id = ++stderrCounter;
      const stderrFile = `/tmp/_stderr_${id}_${Date.now()}`;
      const raw = shellEscape(cmd, args);
      const baseCmd = opts?.sudo ? `sudo ${raw}` : raw;
      const command = `${envPrefix(opts?.env)}${baseCmd}`;
      const wrappedCmd = `${command} 2>${stderrFile}; _exit=$?; cat ${stderrFile} >&2; rm -f ${stderrFile}; exit $_exit`;
      try {
        if (opts?.detached) {
          sandbox.process.executeCommand(`nohup ${command} > /dev/null 2>&1 &`, opts?.cwd).catch(() => {});
          return { stdout: '', stderr: '', exitCode: 0 };
        }
        const result = await sandbox.process.executeCommand(wrappedCmd, opts?.cwd);
        return {
          stdout: result.result ?? '',
          stderr: '', // Daytona mixes stdout/stderr — best effort
          exitCode: result.exitCode,
        };
      } catch (err: any) {
        // Daytona throws DaytonaError for non-zero exits
        return {
          stdout: '',
          stderr: err.message ?? '',
          exitCode: err.exitCode ?? 1,
        };
      }
    },
    async writeFile(path, content) {
      await sandbox.fs.uploadFile(
        Buffer.from(typeof content === 'string' ? content : content),
        path,
      );
    },
    async readFile(path) {
      return sandbox.fs.downloadFile(path);
    },
    async stop() {
      // Note: stopping a Daytona sandbox requires the Daytona client reference
      // which the adapter doesn't hold. This is a no-op.
    },
  };
}

/**
 * Returns Daytona-optimized defaults for SecureConfig.
 *
 * Extends agentDefault() with Daytona-specific paths:
 * - /home/daytona/** home directory
 * - Broad /etc read (Daytona VMs have safe /etc)
 * - /dev/** and /run/** access
 * - GitLab and Bitbucket network access
 * - Daytona API network access
 */
export function daytonaDefaults(): Partial<SecureConfig> {
  const policy = mergePrepend(agentDefault(), {
    file: [
      // Daytona home directory
      { allow: ['/home/daytona', '/home/daytona/**'], ops: ['read', 'write', 'create', 'open', 'stat', 'list', 'readlink', 'mkdir', 'chmod', 'rename'] },
      { softDelete: ['/home/daytona/**', '/workspace/**'] },
      // Broad /etc read
      { allow: ['/etc', '/etc/**'], ops: ['read', 'open', 'stat', 'list', 'readlink'] },
      // Device and runtime files
      { allow: '/dev/**', ops: ['read', 'write', 'open', 'stat', 'list', 'readlink'] },
      { allow: '/run/**', ops: ['read', 'open', 'stat', 'list', 'readlink'] },
    ],
    network: [
      // GitLab
      { allow: ['gitlab.com', '*.gitlab.com'], ports: [443, 22] },
      // Bitbucket
      { allow: ['bitbucket.org', '*.bitbucket.org'], ports: [443, 22] },
      // Daytona API
      { allow: ['app.daytona.io', '*.daytona.io', 'api.daytona.io'], ports: [443] },
    ],
  });

  return { policy };
}
