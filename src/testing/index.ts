import type { SecuredSandbox, ExecResult, SecurityMode } from '../core/types.js';

interface MockConfig {
  commands?: Record<string, ExecResult>;
  files?: Record<string, string>;
}

interface MockOptions {
  securityMode?: SecurityMode;
  sessionId?: string;
}

export function mockSecuredSandbox(config: MockConfig, opts?: MockOptions): SecuredSandbox {
  const files = new Map(Object.entries(config.files ?? {}));
  const commands = config.commands ?? {};

  return {
    sessionId: opts?.sessionId ?? 'mock-session',
    securityMode: opts?.securityMode ?? 'full',

    async exec(command) {
      if (command in commands) return commands[command];
      return { stdout: '', stderr: `mock: no response for "${command}"`, exitCode: 1 };
    },

    async writeFile(path, content) {
      files.set(path, content);
      return { success: true as const, path };
    },

    async readFile(path) {
      const content = files.get(path);
      if (content !== undefined) {
        return { success: true as const, path, content };
      }
      return { success: false as const, path, error: `mock: file not found "${path}"` };
    },

    async stop() {},
  };
}
