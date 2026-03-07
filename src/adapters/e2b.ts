import type { SandboxAdapter } from '../core/types.js';
import { shellEscape } from '../core/shell.js';

export function e2b(sandbox: any): SandboxAdapter {
  return {
    async exec(cmd, args, opts) {
      const command = shellEscape(cmd, args);
      const result = await sandbox.commands.run(command, {
        cwd: opts?.cwd,
        user: opts?.sudo ? 'root' : 'user',
      });
      return {
        stdout: result.stdout ?? '',
        stderr: result.stderr ?? '',
        exitCode: result.exitCode,
      };
    },
    async writeFile(path, content) {
      await sandbox.files.write(path, content);
    },
    async readFile(path) {
      return sandbox.files.read(path);
    },
    async stop() {
      await sandbox.kill();
    },
  };
}
