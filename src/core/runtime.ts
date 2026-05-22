import type {
  SandboxAdapter,
  SecuredSandbox,
  SecurityMode,
  ExecResult,
} from './types.js';
import { RuntimeError } from './errors.js';
import { getTraceparent } from './traceparent.js';

interface ExecEnvelope {
  result?: {
    exit_code?: number;
    stdout?: string;
    stderr?: string;
    error?: {
      code?: string;
      message?: string;
      policy_rule?: string;
    };
  };
}

const WRAP_NOISE_PREFIXES = [
  'agentsh: FUSE workspace mount:',
  'agentsh: LLM proxy:',
  'agentsh: agent ',
  'signal filter: load seccomp filter:',
  'yama: not active, skipping PR_SET_PTRACER',
  // agentsh-unixwrap writes this slog.Info line to the wrapped command's
  // stderr on every successful filter install — see agentsh
  // internal/netmonitor/unix/seccomp_linux.go:500. Until upstream routes
  // it off the user-visible stderr, strip it here so it doesn't leak
  // into writeFile/exec error messages.
  'seccomp: filter loaded',
];

// Agentsh ≥0.20 uses Go's slog text handler which prefixes lines with a
// level token ("INFO ", "WARN ", etc.) before the actual content. Strip
// that prefix before testing against WRAP_NOISE_PREFIXES so e.g.
// "INFO agentsh: agent foo" still matches the "agentsh: agent " entry.
const SLOG_LEVEL = /^(?:debug|info|warn|warning|error)\s+/i;

/** Build env object with TRACEPARENT if an OTEL span is active. */
async function traceEnv(): Promise<Record<string, string> | undefined> {
  const tp = await getTraceparent();
  return tp ? { TRACEPARENT: tp } : undefined;
}

function parseExecEnvelope(raw: ExecResult): ExecEnvelope | null {
  try {
    return JSON.parse(raw.stdout) as ExecEnvelope;
  } catch {
    return null;
  }
}

/** Parse the JSON envelope from `agentsh exec --output json`. */
function parseExecJson(raw: ExecResult): ExecResult {
  const json = parseExecEnvelope(raw);
  if (json) {
    const result = json.result ?? {};
    return {
      exitCode: result.exit_code ?? raw.exitCode,
      stdout: result.stdout ?? '',
      // Sanitize the inner stderr — the wrapped command inherits
      // agentsh-unixwrap's stderr fd, so unixwrap's INFO/diagnostic
      // lines end up mixed into the user-visible stream here.
      stderr: sanitizeWrapStream(result.stderr ?? result.error?.message ?? ''),
    };
  }

  // If not valid JSON, return as-is (e.g. mock adapters)
  return raw;
}

function isOpaqueShellPolicyDeny(raw: ExecResult): boolean {
  const json = parseExecEnvelope(raw);
  const result = json?.result;
  return (
    (result?.exit_code ?? raw.exitCode) === 126
    && result?.error?.code === 'E_POLICY_DENIED'
    && result?.error?.policy_rule === 'shellc-opaque-script'
  );
}

function sanitizeWrapStream(text: string): string {
  if (!text) {
    return text;
  }

  let normalized = text;
  for (const marker of WRAP_NOISE_PREFIXES) {
    normalized = normalized.replaceAll(marker, `\n${marker}`);
  }

  return normalized
    .split('\n')
    .filter((line) => {
      if (!line) return false;
      const stripped = line.replace(SLOG_LEVEL, '');
      // Lines that are just a slog level prefix (split off by the
      // replaceAll above) collapse to empty after stripping — drop them.
      if (!stripped) return false;
      return !WRAP_NOISE_PREFIXES.some((prefix) => stripped.startsWith(prefix))
        && !/^\d{4}\/\d{2}\/\d{2} .*ERROR wrap: failed to receive notify fd from wrapper/.test(line);
    })
    .join('\n');
}

function sanitizeWrapResult(result: ExecResult): ExecResult {
  return {
    ...result,
    stdout: sanitizeWrapStream(result.stdout),
    stderr: sanitizeWrapStream(result.stderr),
  };
}

async function runExecJson(
  adapter: SandboxAdapter,
  sessionId: string,
  request: {
    command: string;
    args?: string[];
    stdin?: string;
    include_events?: 'all' | 'summary' | 'blocked' | 'none';
  },
  opts?: {
    cwd?: string;
    env?: Record<string, string>;
  },
): Promise<ExecResult> {
  const result = await adapter.exec(
    'agentsh',
    [
      'exec',
      '--output',
      'json',
      sessionId,
      '--json',
      JSON.stringify(request),
    ],
    opts,
  );
  if (isTransportFailure(result)) {
    throw new RuntimeError({
      sessionId,
      command: `${request.command} ${request.args?.join(' ') ?? ''}`.trim(),
      stderr: result.stderr,
    });
  }
  return parseExecJson(result);
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
      const env = await traceEnv();
      const execOpts = { cwd: opts?.cwd, env };
      const result = await adapter.exec('agentsh', args, execOpts);
      if (isTransportFailure(result)) {
        throw new RuntimeError({
          sessionId,
          command,
          stderr: result.stderr,
        });
      }
      if (isOpaqueShellPolicyDeny(result)) {
        const wrapped = await adapter.exec(
          'agentsh',
          [
            'wrap',
            '--session',
            sessionId,
            '--report=false',
            '--',
            'bash',
            '-c',
            command,
          ],
          execOpts,
        );
        if (isTransportFailure(wrapped)) {
          throw new RuntimeError({
            sessionId,
            command,
            stderr: wrapped.stderr,
          });
        }
        return sanitizeWrapResult(wrapped);
      }
      return parseExecJson(result);
    },

    async writeFile(path, content) {
      const env = await traceEnv();
      const result = await runExecJson(adapter, sessionId, {
        command: 'tee',
        args: [path],
        stdin: content,
        include_events: 'summary',
      }, { env });
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
      const env = await traceEnv();
      const result = await runExecJson(adapter, sessionId, {
        command: 'cat',
        args: [path],
        include_events: 'summary',
      }, { env });
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
