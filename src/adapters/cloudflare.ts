import type { SandboxAdapter } from '../core/types.js';
import { shellEscape } from '../core/shell.js';

export function cloudflare(sandbox: any): SandboxAdapter {
  return {
    async exec(cmd, args, opts) {
      let command = shellEscape(cmd, args);
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
