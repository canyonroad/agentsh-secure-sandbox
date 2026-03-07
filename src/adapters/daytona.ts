import type { SandboxAdapter } from '../core/types.js';
import { shellEscape } from '../core/shell.js';

let stderrCounter = 0;

export function daytona(sandbox: any): SandboxAdapter {
  return {
    async exec(cmd, args, opts) {
      const id = ++stderrCounter;
      const stderrFile = `/tmp/_stderr_${id}_${Date.now()}`;
      const command = shellEscape(cmd, args);
      const wrappedCmd = `${command} 2>${stderrFile}; _exit=$?; cat ${stderrFile} >&2; rm -f ${stderrFile}; exit $_exit`;
      const result = await sandbox.process.executeCommand(wrappedCmd, { cwd: opts?.cwd });
      return {
        stdout: result.result ?? '',
        stderr: '', // Daytona mixes stdout/stderr — best effort
        exitCode: result.exitCode,
      };
    },
    async writeFile(path, content) {
      await sandbox.fs.uploadFile(path, Buffer.from(typeof content === 'string' ? content : content));
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
