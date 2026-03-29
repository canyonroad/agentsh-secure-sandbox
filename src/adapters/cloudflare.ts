import type { SandboxAdapter, SecureConfig } from '../core/types.js';
import { shellEscape, envPrefix } from '../core/shell.js';
import { agentDefault } from '../policies/presets.js';
import { mergePrepend } from '../policies/merge.js';

export function cloudflare(sandbox: any): SandboxAdapter {
  return {
    async exec(cmd, args, opts) {
      let command = `${envPrefix(opts?.env)}${shellEscape(cmd, args)}`;
      // Cloudflare containers run as root — sudo is unnecessary and often
      // not installed.  Silently drop the flag so provisioning works.
      // (No-op: sudo requests are simply run directly as root.)

      if (opts?.detached) {
        // Fire-and-forget for daemon processes
        sandbox.exec(`nohup ${command} > /dev/null 2>&1 &`, { cwd: opts?.cwd }).catch(() => {});
        return { stdout: '', stderr: '', exitCode: 0 };
      }

      const result = await sandbox.exec(command, { cwd: opts?.cwd });
      return {
        stdout: result.stdout ?? '',
        stderr: result.stderr ?? '',
        exitCode: result.exitCode,
      };
    },
    async writeFile(path, content) {
      const buf = Buffer.isBuffer(content) ? content : Buffer.from(content);
      const b64 = buf.toString('base64');
      const cmd = shellEscape('sh', ['-c', 'printf "%s" "$1" | base64 -d > "$2"', '_', b64, path]);
      const result = await sandbox.exec(cmd);
      if ((result.exitCode ?? 0) !== 0) {
        throw new Error(`writeFile failed (exit ${result.exitCode}): ${result.stderr ?? ''}`);
      }
    },
    async readFile(path) {
      const cmd = shellEscape('cat', [path]);
      const result = await sandbox.exec(cmd);
      if ((result.exitCode ?? 0) !== 0) {
        throw new Error(`readFile failed (exit ${result.exitCode}): ${result.stderr ?? ''}`);
      }
      return result.stdout ?? '';
    },
    async stop() {
      // No-op — Cloudflare manages container lifecycle
    },
  };
}

/**
 * Returns Cloudflare-optimized defaults for SecureConfig.
 *
 * Extends agentDefault() with Cloudflare-specific paths:
 * - /home/sandbox/** home directory
 * - Broader /etc read (profile, alternatives, python, pip, gitconfig)
 * - /dev/shm/** for shared memory
 */
export function cloudflareDefaults(): Partial<SecureConfig> {
  const policy = mergePrepend(agentDefault(), {
    file: [
      // Cloudflare sandbox home directory
      { allow: '/home/sandbox/**', ops: ['read', 'write', 'create', 'open', 'stat', 'list', 'readlink', 'mkdir', 'chmod', 'rename'] },
      { softDelete: '/home/sandbox/**' },
      // Broader /etc read for Cloudflare containers
      { allow: [
        '/etc/gai.conf', '/etc/bash.bashrc', '/etc/profile', '/etc/profile.d/**',
        '/etc/environment', '/etc/alternatives/**', '/etc/pip.conf',
        '/etc/python3/**', '/etc/gitconfig',
      ], ops: ['read', 'open', 'stat', 'readlink'] },
      // Shared memory
      { allow: '/dev/shm/**', ops: ['read', 'write', 'open', 'stat'] },
    ],
  });

  return { policy };
}
