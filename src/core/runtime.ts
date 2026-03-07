import type {
  SandboxAdapter,
  SecuredSandbox,
  SecurityMode,
  ExecResult,
} from './types.js';
import { RuntimeError } from './errors.js';

export function createSecuredSandbox(
  adapter: SandboxAdapter,
  sessionId: string,
  securityMode: SecurityMode,
): SecuredSandbox {
  return {
    sessionId,
    securityMode,

    async exec(command, opts) {
      const args = [
        'exec',
        '--output',
        'json',
        sessionId,
        '--',
        'bash',
        '-c',
        command,
      ];
      const execOpts = opts?.cwd ? { cwd: opts.cwd } : undefined;
      const result = await adapter.exec('agentsh', args, execOpts);
      if (isTransportFailure(result)) {
        throw new RuntimeError({
          sessionId,
          command,
          stderr: result.stderr,
        });
      }
      return result;
    },

    async writeFile(path, content) {
      const b64 = Buffer.from(content, 'utf-8').toString('base64');
      const args = [
        'exec',
        sessionId,
        '--',
        'sh',
        '-c',
        'printf "%s" "$1" | base64 -d > "$2"',
        '_',
        b64,
        path,
      ];
      const result = await adapter.exec('agentsh', args);
      if (isTransportFailure(result)) {
        throw new RuntimeError({
          sessionId,
          command: `writeFile ${path}`,
          stderr: result.stderr,
        });
      }
      if (result.exitCode !== 0) {
        return {
          success: false as const,
          path,
          error: result.stderr || 'writeFile failed',
        };
      }
      return { success: true as const, path };
    },

    async readFile(path) {
      const args = ['exec', sessionId, '--', 'cat', path];
      const result = await adapter.exec('agentsh', args);
      if (isTransportFailure(result)) {
        throw new RuntimeError({
          sessionId,
          command: `readFile ${path}`,
          stderr: result.stderr,
        });
      }
      if (result.exitCode !== 0) {
        return {
          success: false as const,
          path,
          error: result.stderr || 'readFile failed',
        };
      }
      return { success: true as const, path, content: result.stdout };
    },

    async stop() {
      await adapter.stop?.();
    },
  };
}

function isTransportFailure(result: ExecResult): boolean {
  return result.exitCode === 127 && result.stderr.includes('agentsh');
}
