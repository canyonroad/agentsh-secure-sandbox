import type { SandboxAdapter } from '../core/types.js';

export function vercel(sandbox: any): SandboxAdapter {
  return {
    async exec(cmd, args, opts) {
      const params: Record<string, unknown> = {
        cmd,
        args: args ?? [],
      };
      if (opts?.cwd) params.cwd = opts.cwd;
      if (opts?.sudo) params.sudo = opts.sudo;
      if (opts?.detached) params.detached = opts.detached;
      const result = await sandbox.runCommand(params);

      // Detached processes return exitCode: null and stdout/stderr may hang
      if (opts?.detached) {
        return { stdout: '', stderr: '', exitCode: result.exitCode ?? 0 };
      }

      return {
        stdout: typeof result.stdout === 'function' ? await result.stdout() : result.stdout,
        stderr: typeof result.stderr === 'function' ? await result.stderr() : result.stderr,
        exitCode: result.exitCode,
      };
    },
    async writeFile(path, content, opts) {
      const buf = Buffer.isBuffer(content) ? content : Buffer.from(content);
      await sandbox.writeFiles([{ path, content: buf }]);
    },
    async readFile(path) {
      const stream = await sandbox.readFile({ path });
      if (!stream) return '';
      const chunks: Buffer[] = [];
      for await (const chunk of stream) {
        chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
      }
      return Buffer.concat(chunks).toString('utf-8');
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
