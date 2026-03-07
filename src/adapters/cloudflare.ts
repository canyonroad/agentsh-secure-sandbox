import type { SandboxAdapter } from '../core/types.js';
import { shellEscape } from '../core/shell.js';

export function cloudflare(sandbox: any): SandboxAdapter {
  return {
    async exec(cmd, args, opts) {
      let command = shellEscape(cmd, args);
      if (opts?.sudo) command = `sudo ${command}`;

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
      await sandbox.exec(`printf '%s' '${b64}' | base64 -d > '${path}'`);
    },
    async readFile(path) {
      const result = await sandbox.exec(`cat '${path}'`);
      return result.stdout ?? '';
    },
    async stop() {
      // No-op — Cloudflare manages container lifecycle
    },
  };
}
