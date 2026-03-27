import type { SandboxAdapter, SecureConfig } from '../core/types.js';
import { agentDefault } from '../policies/presets.js';
import { mergePrepend } from '../policies/merge.js';

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
      if (opts?.env) params.env = opts.env;
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

/**
 * Returns Vercel-optimized defaults for SecureConfig.
 *
 * Extends agentDefault() with Vercel-specific paths:
 * - /vercel/sandbox/** workspace
 * - /home/vercel-sandbox/** home directory
 * - Broad /etc read (Vercel images have safe /etc)
 * - /opt/** for Vercel-installed runtimes
 */
export function vercelDefaults(): Partial<SecureConfig> {
  const policy = mergePrepend(agentDefault(), {
    file: [
      // Vercel sandbox workspace
      { allow: ['/vercel/sandbox', '/vercel/sandbox/**'], ops: ['read', 'write', 'create', 'open', 'stat', 'list', 'readlink', 'mkdir', 'chmod', 'rename'] },
      { softDelete: ['/vercel/sandbox', '/vercel/sandbox/**'] },
      // Vercel home directory
      { allow: ['/home/vercel-sandbox', '/home/vercel-sandbox/**'], ops: ['read', 'write', 'create', 'open', 'stat', 'list', 'readlink', 'mkdir', 'chmod', 'rename'] },
      { softDelete: '/home/vercel-sandbox/**' },
      // Broad /etc read (Vercel Firecracker VMs have safe /etc)
      { allow: ['/etc', '/etc/**'], ops: ['read', 'open', 'stat', 'list', 'readlink'] },
      // Vercel-installed runtimes in /opt
      { allow: '/opt/**', ops: ['read', 'open', 'stat', 'list', 'readlink'] },
    ],
  });

  return { policy };
}
