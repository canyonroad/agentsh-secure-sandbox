import type { SandboxAdapter, SecureConfig } from '../core/types.js';
import type { ServerConfigOpts } from '../core/config.js';
import { shellEscape, envPrefix } from '../core/shell.js';

/**
 * Wraps a Modal Sandbox object into a SandboxAdapter.
 *
 * Modal sandboxes run on gVisor which lacks seccomp user-notify and
 * full FUSE support. Use `modalDefaults()` to get ptrace-optimized
 * configuration that works on gVisor.
 *
 * The `sandbox` parameter is typed as `any` to avoid a hard dependency
 * on the Modal SDK — pass any object whose `.exec()` accepts variadic
 * string arguments and returns a process with `.stdout.read()`,
 * `.stderr.read()`, `.returncode`, and `.wait()`.
 */
export function modal(sandbox: any): SandboxAdapter {
  async function run(cmd: string): Promise<{ stdout: string; stderr: string; exitCode: number }> {
    try {
      const proc = await sandbox.exec('sh', '-c', cmd);
      await proc.wait();
      const stdout = typeof proc.stdout?.read === 'function' ? await proc.stdout.read() : (proc.stdout ?? '');
      const stderr = typeof proc.stderr?.read === 'function' ? await proc.stderr.read() : (proc.stderr ?? '');
      const exitCode = proc.returncode ?? proc.exitCode ?? 0;
      return { stdout, stderr, exitCode };
    } catch (err: any) {
      return {
        stdout: err.stdout ?? '',
        stderr: err.stderr ?? err.message ?? '',
        exitCode: err.returncode ?? err.exitCode ?? err.code ?? 1,
      };
    }
  }

  return {
    async exec(cmd, args, opts) {
      // Modal containers run as root — drop sudo
      const command = `${envPrefix(opts?.env)}${shellEscape(cmd, args)}`;

      if (opts?.detached) {
        run(`nohup ${command} > /dev/null 2>&1 &`).catch(() => {});
        return { stdout: '', stderr: '', exitCode: 0 };
      }

      return run(command);
    },

    async writeFile(path, content) {
      const buf = Buffer.isBuffer(content) ? content : Buffer.from(content);
      const b64 = buf.toString('base64');
      const result = await run(
        `printf '%s' '${b64}' | base64 -d > '${path.replace(/'/g, "'\\''")}'`,
      );
      if (result.exitCode !== 0) {
        throw new Error(
          `writeFile failed (exit ${result.exitCode}): ${result.stderr}`,
        );
      }
    },

    async readFile(path) {
      const result = await run(`cat '${path.replace(/'/g, "'\\''")}'`);
      if (result.exitCode !== 0) {
        throw new Error(
          `readFile failed (exit ${result.exitCode}): ${result.stderr}`,
        );
      }
      return result.stdout;
    },

    async stop() {
      await sandbox.terminate?.();
    },
  };
}

/**
 * Returns Modal-optimized defaults for SecureConfig.
 *
 * Key differences from other providers:
 * - ptrace enabled (gVisor blocks seccomp user-notify)
 * - seccomp_prefilter disabled (gVisor blocks BPF injection)
 * - FUSE deferred (may not be available on gVisor)
 * - unix_sockets disabled (mutually exclusive with ptrace)
 * - cgroups disabled (Modal handles resource limits)
 * - allow_degraded enabled (graceful fallback for FUSE/seccomp)
 *
 * Spread into your secureSandbox() call:
 *
 *   secureSandbox(modal(sb), { ...modalDefaults(), ...yourOverrides })
 */
export function modalDefaults(): Partial<SecureConfig> {
  const serverConfig: Omit<ServerConfigOpts, 'watchtower' | 'realPaths' | 'threatFeeds' | 'packageChecks'> = {
    grpc: { addr: '127.0.0.1:9090' },
    logging: { level: 'info', format: 'text', output: 'stderr' },
    sessions: {
      defaultTimeout: '1h',
      idleTimeout: '15m',
      cleanupInterval: '5m',
    },
    audit: { enabled: true, sqlitePath: '/var/lib/agentsh/events.db' },
    sandboxLimits: { maxMemoryMb: 4096, maxCpuPercent: 100, maxProcesses: 256 },
    allowDegraded: true,
    fuse: {
      deferred: true,
      deferredMarkerFile: '/tmp/.agentsh-fuse-enabled',
      deferredEnableCommand: ['/bin/chmod', '666', '/dev/fuse'],
    },
    networkIntercept: { interceptMode: 'all', proxyListenAddr: '127.0.0.1:0' },
    cgroups: { enabled: false },
    unixSockets: { enabled: false },
    ptrace: {
      enabled: true,
      attachMode: 'children',
      maskTracerPid: 'off',
      trace: {
        execve: true,
        file: true,
        network: true,
        signal: true,
      },
      performance: {
        seccompPrefilter: false,
        maxTracees: 500,
        maxHoldMs: 5000,
      },
      onAttachFailure: 'fail_open',
    },
    envInject: {
      BASH_ENV: '/usr/lib/agentsh/bash_startup.sh',
    },
    dlp: {
      mode: 'redact',
      patterns: { api_keys: true, credit_card: true, ssn: true },
    },
    approvals: { enabled: false },
    metrics: { enabled: true, path: '/metrics' },
    health: { path: '/health', readinessPath: '/ready' },
  };

  return {
    installStrategy: 'download',
    realPaths: true,
    serverConfig,
  };
}
