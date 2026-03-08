import type { SandboxAdapter } from '../core/types.js';
import { shellEscape, envPrefix } from '../core/shell.js';

export function e2b(sandbox: any): SandboxAdapter {
  return {
    async exec(cmd, args, opts) {
      const command = `${envPrefix(opts?.env)}${shellEscape(cmd, args)}`;
      try {
        if (opts?.detached) {
          sandbox.commands.run(`nohup ${command} > /dev/null 2>&1 &`, {
            cwd: opts?.cwd,
            user: opts?.sudo ? 'root' : 'user',
          }).catch(() => {});
          return { stdout: '', stderr: '', exitCode: 0 };
        }
        const result = await sandbox.commands.run(command, {
          cwd: opts?.cwd,
          user: opts?.sudo ? 'root' : 'user',
        });
        return {
          stdout: result.stdout ?? '',
          stderr: result.stderr ?? '',
          exitCode: result.exitCode,
        };
      } catch (err: any) {
        // E2B throws CommandExitError for non-zero exits
        return {
          stdout: err.stdout ?? '',
          stderr: err.stderr ?? err.message ?? '',
          exitCode: err.exitCode ?? 1,
        };
      }
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
