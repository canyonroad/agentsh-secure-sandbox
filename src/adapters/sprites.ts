import type { SandboxAdapter, SecureConfig } from '../core/types.js';
import type { ServerConfigOpts } from '../core/config.js';
import { shellEscape, envPrefix } from '../core/shell.js';

export function sprites(sprite: any): SandboxAdapter {
  // sprite.exec() does a naive split(/\s+/) — no shell parsing.
  // Use sprite.execFile('sh', ['-c', cmd]) for shell features (env, pipes, quotes).
  function sh(cmd: string, opts?: Record<string, unknown>) {
    if (opts) return sprite.execFile('sh', ['-c', cmd], opts);
    return sprite.execFile('sh', ['-c', cmd]);
  }

  return {
    async exec(cmd, args, opts) {
      const command = `${envPrefix(opts?.env)}${shellEscape(cmd, args)}`;
      const fullCmd = opts?.sudo ? `sudo ${command}` : command;

      try {
        if (opts?.detached) {
          sh(`nohup ${fullCmd} > /dev/null 2>&1 &`).catch(() => {});
          return { stdout: '', stderr: '', exitCode: 0 };
        }

        const result = await sh(fullCmd, { cwd: opts?.cwd });
        return {
          stdout: result.stdout ?? '',
          stderr: result.stderr ?? '',
          exitCode: 0,
        };
      } catch (err: any) {
        return {
          stdout: err.stdout ?? '',
          stderr: err.stderr ?? err.message ?? '',
          exitCode: err.exitCode ?? err.code ?? 1,
        };
      }
    },
    async writeFile(path, content) {
      const buf = Buffer.isBuffer(content) ? content : Buffer.from(content);
      const b64 = buf.toString('base64');
      try {
        await sh(`printf '%s' '${b64}' | base64 -d > '${path.replace(/'/g, "'\\''")}'`);
      } catch (err: any) {
        throw new Error(`writeFile failed (exit ${err.exitCode ?? err.code ?? 1}): ${err.stderr ?? err.message ?? ''}`);
      }
    },
    async readFile(path) {
      try {
        const result = await sh(`cat '${path.replace(/'/g, "'\\''")}'`);
        return result.stdout ?? '';
      } catch (err: any) {
        throw new Error(`readFile failed (exit ${err.exitCode ?? err.code ?? 1}): ${err.stderr ?? err.message ?? ''}`);
      }
    },
    async stop() {
      await sprite.delete();
    },
  };
}

/**
 * Returns Sprites-optimized defaults for SecureConfig.
 * Spread into your secureSandbox() call:
 *
 *   secureSandbox(sprites(s), { ...spritesDefaults(), ...yourOverrides })
 */
export function spritesDefaults(): Partial<SecureConfig> {
  const serverConfig: Omit<ServerConfigOpts, 'watchtower' | 'realPaths' | 'threatFeeds' | 'packageChecks'> = {
    grpc: { addr: '0.0.0.0:50051' },
    logging: { level: 'info', format: 'json', output: 'stdout' },
    sessions: {
      defaultTimeout: '30m',
      idleTimeout: '10m',
      cleanupInterval: '5m',
    },
    audit: { enabled: true, sqlitePath: '/var/lib/agentsh/audit.db' },
    sandboxLimits: { maxMemoryMb: 512, maxCpuPercent: 90, maxProcesses: 100 },
    fuse: { deferred: true },
    networkIntercept: { interceptMode: 'tproxy', proxyListenAddr: '127.0.0.1:8888' },
    seccompDetails: {
      execve: true,
      fileMonitor: { enabled: true, enforceWithoutFuse: true },
    },
    cgroups: { enabled: true },
    unixSockets: { enabled: true },
    proxy: { mode: 'mitm', port: 8080 },
    dlp: {
      mode: 'redact',
      patterns: { credit_card: true, ssn: true, api_key: true },
    },
    approvals: { enabled: false },
    metrics: { enabled: true, path: '/metrics' },
    health: { path: '/healthz', readinessPath: '/readyz' },
    development: { disableAuth: false, verboseErrors: false },
  };

  return {
    installStrategy: 'preinstalled',
    realPaths: true,
    serverConfig,
  };
}
