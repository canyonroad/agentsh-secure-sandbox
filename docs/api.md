# API Reference

## `secureSandbox(adapter, config?)`

Secures any sandbox via its adapter. Returns a `SecuredSandbox` that mediates every command, file read, and file write through the [agentsh](https://www.agentsh.org) policy engine.

```typescript
import { secureSandbox } from '@agentsh/secure-sandbox';

const sandbox = await secureSandbox(adapter, {
  policy: agentDefault(),              // Policy to enforce (default: agentDefault())
  installStrategy: 'download',         // 'download' | 'upload' | 'preinstalled' | 'running'
  agentshVersion: '0.15.0',            // agentsh binary version
  minimumSecurityMode: 'landlock',     // Fail if kernel can't enforce this level
  threatFeeds: true,                   // Enable/disable/customize threat intelligence feeds
});
```

### Config Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `policy` | `Policy` | `agentDefault()` | Policy rules for file, network, and command access |
| `installStrategy` | `string` | `'download'` | How to install the agentsh binary in the sandbox |
| `agentshVersion` | `string` | Latest | Pin a specific agentsh version |
| `minimumSecurityMode` | `SecurityMode` | `undefined` | Fail if the sandbox kernel can't enforce at least this level |
| `securityMode` | `SecurityMode` | `undefined` | Override detected security mode. Only used with `'running'` strategy (defaults to `'full'`). |
| `sessionId` | `string` | `undefined` | Existing agentsh session ID. Only used with `'running'` strategy. Falls back to `$AGENTSH_SESSION_ID`. |
| `threatFeeds` | `boolean \| ThreatFeedConfig` | `true` | Threat intelligence feed configuration |

### Install Strategies

| Strategy | When to Use |
|----------|-------------|
| `'download'` | Default — downloads agentsh from GitHub releases inside the sandbox |
| `'upload'` | Upload a local agentsh binary to the sandbox (useful for air-gapped environments) |
| `'preinstalled'` | agentsh is already installed in the sandbox image |
| `'running'` | agentsh is already running — skip installation and startup entirely |

## `SecuredSandbox`

The interface returned by `secureSandbox()`. Every operation is mediated by the policy engine.

```typescript
interface SecuredSandbox {
  exec(command: string, opts?: { cwd?: string; timeout?: number }): Promise<ExecResult>;
  writeFile(path: string, content: string): Promise<WriteFileResult>;
  readFile(path: string): Promise<ReadFileResult>;
  stop(): Promise<void>;
  readonly sessionId: string;
  readonly securityMode: SecurityMode;
}
```

### `exec(command, opts?)`

Run a shell command. The command is routed through the agentsh shell shim, which evaluates it against the policy before execution.

```typescript
const result = await sandbox.exec('npm install express');
// { stdout: '...', stderr: '...', exitCode: 0 }

const result = await sandbox.exec('cat .env');
// { stdout: '', stderr: 'denied by policy: file access blocked', exitCode: 126 }
```

### `writeFile(path, content)`

Write a file to the sandbox. File path is checked against file policy rules.

```typescript
await sandbox.writeFile('/workspace/index.js', 'console.log("hello")');
```

### `readFile(path)`

Read a file from the sandbox. File path is checked against file policy rules.

```typescript
const content = await sandbox.readFile('/workspace/index.js');
```

### `stop()`

Stop the sandbox and clean up resources.

### `sessionId`

Unique identifier for this secured sandbox session.

### `securityMode`

The actual security mode negotiated with the sandbox kernel. See [Security Modes](#security-modes).

## Security Modes

The security level depends on what the sandbox kernel supports. `secureSandbox()` automatically negotiates the highest available mode.

| Mode | Enforcement | Typical Platform |
|------|-------------|-----------------|
| `full` | seccomp + FUSE + Landlock + network proxy | Full Linux with FUSE support (E2B, Daytona, Blaxel) |
| `landlock` | seccomp + Landlock + network proxy (no FUSE) | Firecracker VMs (Vercel, Cloudflare) |
| `landlock-only` | Landlock filesystem restrictions only | Limited kernel support |
| `minimal` | Policy evaluation only, no kernel enforcement | Containers without seccomp |

Use `minimumSecurityMode` to fail fast if the sandbox can't meet your security requirements:

```typescript
const sandbox = await secureSandbox(vercel(raw), {
  minimumSecurityMode: 'landlock', // Throws if kernel can't enforce this level
});

console.log(sandbox.securityMode); // 'landlock'
```

## Custom Adapter

Any sandbox that can run commands works with `secureSandbox()`. Implement the `SandboxAdapter` interface:

```typescript
import { secureSandbox } from '@agentsh/secure-sandbox';
import type { SandboxAdapter } from '@agentsh/secure-sandbox';

const myAdapter: SandboxAdapter = {
  async exec(cmd, args, opts) {
    // Your sandbox's exec implementation
    return { stdout: '', stderr: '', exitCode: 0 };
  },
  async writeFile(path, content) { /* ... */ },
  async readFile(path) { /* ... */ },
};

const sandbox = await secureSandbox(myAdapter);
```

The adapter must implement three methods:

| Method | Signature | Description |
|--------|-----------|-------------|
| `exec` | `(cmd: string, args: string[], opts?: ExecOpts) => Promise<ExecResult>` | Execute a command in the sandbox |
| `writeFile` | `(path: string, content: string) => Promise<void>` | Write a file to the sandbox filesystem |
| `readFile` | `(path: string) => Promise<string>` | Read a file from the sandbox filesystem |

## Testing

Mock utilities for unit testing without a real sandbox:

```typescript
import { mockSecuredSandbox } from '@agentsh/secure-sandbox/testing';

const sandbox = mockSecuredSandbox({
  execResults: [{ stdout: 'hello\n', stderr: '', exitCode: 0 }],
  securityMode: 'full',
});

const result = await sandbox.exec('echo hello');
expect(result.stdout).toBe('hello\n');
```

`mockSecuredSandbox` returns a `SecuredSandbox` that replays canned responses without any sandbox or policy engine. Use it in unit tests to verify your agent logic without spinning up real infrastructure.

### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `execResults` | `ExecResult[]` | `[]` | Responses to return from `exec()`, consumed in order |
| `readFileResults` | `string[]` | `[]` | Responses to return from `readFile()` |
| `writeFileResults` | `WriteFileResult[]` | `[]` | Responses to return from `writeFile()` |
| `securityMode` | `SecurityMode` | `'full'` | The `securityMode` property value |
| `sessionId` | `string` | Random UUID | The `sessionId` property value |
