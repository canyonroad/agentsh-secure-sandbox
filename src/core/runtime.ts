import type {
  SandboxAdapter,
  SecuredSandbox,
  SecurityMode,
  ExecResult,
} from './types.js';
import { RuntimeError } from './errors.js';

/** Parse the JSON envelope from `agentsh exec --output json`. */
function parseExecJson(raw: ExecResult): ExecResult {
  try {
    const json = JSON.parse(raw.stdout);
    const result = json.result ?? {};
    return {
      exitCode: result.exit_code ?? raw.exitCode,
      stdout: result.stdout ?? '',
      stderr: result.stderr ?? result.error?.message ?? '',
    };
  } catch {
    // If not valid JSON, return as-is (e.g. mock adapters)
    return raw;
  }
}

export function createSecuredSandbox(
  adapter: SandboxAdapter,
  sessionId: string,
  securityMode: SecurityMode,
  options?: { passthrough?: boolean },
): SecuredSandbox {
  if (options?.passthrough) {
    return createPassthroughSandbox(adapter, sessionId, securityMode);
  }
  return createAgentshSandbox(adapter, sessionId, securityMode);
}

/**
 * Passthrough mode: the shell shim enforces policy on every command,
 * so we run commands directly through the adapter without wrapping
 * them in `agentsh exec`. Used with the 'running' install strategy.
 */
function createPassthroughSandbox(
  adapter: SandboxAdapter,
  sessionId: string,
  securityMode: SecurityMode,
): SecuredSandbox {
  return {
    sessionId,
    securityMode,

    async exec(command, opts) {
      const result = await adapter.exec('bash', ['-c', command], {
        cwd: opts?.cwd,
      });
      return result;
    },

    async writeFile(path, content) {
      const b64 = Buffer.from(content, 'utf-8').toString('base64');
      const result = await adapter.exec('sh', [
        '-c',
        'printf "%s" "$1" | base64 -d > "$2"',
        '_',
        b64,
        path,
      ]);
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
      const result = await adapter.exec('cat', [path]);
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

/** Standard mode: wraps commands in `agentsh exec` for policy enforcement. */
function createAgentshSandbox(
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
      return parseExecJson(result);
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
