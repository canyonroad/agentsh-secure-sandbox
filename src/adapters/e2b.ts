import type { SandboxAdapter, SecureConfig } from '../core/types.js';
import { shellEscape, envPrefix } from '../core/shell.js';
import { agentDefault } from '../policies/presets.js';
import { mergePrepend } from '../policies/merge.js';

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

/**
 * Returns E2B-optimized defaults for SecureConfig.
 *
 * Extends agentDefault() with E2B-specific rules:
 * - Deny E2B infrastructure binaries (envd, socat) and systemd paths
 * - Deny E2B internal network (192.0.2.0/24 TEST-NET-1)
 * - Deny E2B infrastructure commands (iptables, ip, tc, nft)
 */
export function e2bDefaults(): Partial<SecureConfig> {
  const policy = mergePrepend(agentDefault(), {
    file: [
      // Block E2B infrastructure binaries and configs
      { deny: ['/usr/bin/envd', '/usr/bin/socat', '/etc/systemd/**', '/run/systemd/**'] },
    ],
    network: [
      // Block E2B internal services (TEST-NET-1 range)
      { denyCidrs: ['192.0.2.0/24'] },
    ],
    commands: [
      // Block commands that could interfere with E2B infrastructure
      { deny: ['socat', 'envd', 'iptables', 'ip6tables', 'nft', 'tc', 'ip'] },
    ],
  });

  return { policy };
}
