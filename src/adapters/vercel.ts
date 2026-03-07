import type { SandboxAdapter } from '../core/types.js';

export function vercel(sandbox: any): SandboxAdapter {
  return {
    async exec(cmd, args, opts) {
      const result = await sandbox.runCommand({
        cmd,
        args: args ?? [],
        cwd: opts?.cwd,
        sudo: opts?.sudo,
        detached: opts?.detached,
      });
      return {
        stdout: typeof result.stdout === 'function' ? result.stdout() : result.stdout,
        stderr: typeof result.stderr === 'function' ? result.stderr() : result.stderr,
        exitCode: result.exitCode,
      };
    },
    async writeFile(path, content, opts) {
      await sandbox.writeFiles([{ path, content }]);
    },
    async readFile(path) {
      return sandbox.readFile(path);
    },
    async stop() {
      await sandbox.stop();
    },
    async fileExists(path) {
      const result = await sandbox.runCommand({ cmd: 'test', args: ['-f', path] });
      return result.exitCode === 0;
    },
  };
}
