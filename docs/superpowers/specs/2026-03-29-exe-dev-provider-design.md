# exe.dev Provider Adapter Design

## Overview

Add exe.dev as a sandbox provider in `@agentsh/secure-sandbox`. exe.dev provides persistent Ubuntu VMs accessible via SSH through a gateway (`ssh exe.dev ssh <vmName> <cmd>`). Unlike other providers that have SDK clients, exe.dev's interface is pure SSH CLI.

## Files

| File | Action | Purpose |
|------|--------|---------|
| `src/adapters/exe.ts` | Create | Adapter factory + defaults |
| `src/adapters/index.ts` | Edit | Add `exe`, `exeDefaults` exports |
| `src/adapters/adapters.test.ts` | Edit | Add unit tests |
| `package.json` | Edit | Add `./adapters/exe` export path |

## Adapter: `exe(vmName: string): SandboxAdapter`

### Input

Accepts a VM name string (e.g., `'my-agent-vm'`). The VM must already exist (created via `ssh exe.dev new`).

### SSH Communication

Uses promisified `child_process.exec` for non-blocking async SSH. All commands route through the exe.dev gateway:

```
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR exe.dev ssh <vmName> <escaped-command>
```

SSH flags rationale: `StrictHostKeyChecking=no` and `UserKnownHostsFile=/dev/null` are acceptable because the gateway (`exe.dev`) is a known, trusted endpoint — not an arbitrary host.

A helper function `ssh(cmd, timeout?)` wraps this pattern with a default timeout of 120s. Commands pass through two shells (local SSH client -> remote bash), and `shellEscape` produces output safe for this double-interpretation.

Output is filtered to strip agentsh debug noise that leaks through SSH stderr. Filtering uses line-by-line prefix matching for known patterns: lines starting with `landlock:`, `ptrace:`, `agentsh:`, `seccomp:`, or `[agentsh]` are stripped.

### Methods

- **`exec(cmd, args, opts)`** — Shell-escapes command via `shellEscape` + `envPrefix`, routes through SSH. Supports `sudo` (prefixed), `cwd` (cd wrapper), `env` (env prefix), `detached` (nohup background). Catches exec errors and extracts exit codes.
- **`writeFile(path, content)`** — Base64-encodes content, pipes through SSH: `printf '%s' '<b64>' | base64 -d > '<path>'`. Same pattern as cloudflare/modal/sprites adapters.
- **`readFile(path)`** — `cat <path>` via SSH.
- **`stop()`** — No-op. exe.dev VMs are persistent and should not be destroyed on stop. Users manage VM lifecycle externally via `ssh exe.dev rm <vmName>`.
- **`fileExists(path)`** — `test -f <path>` via SSH. Enables fast detection of pre-installed agentsh binary.

## Defaults: `exeDefaults(): Partial<SecureConfig>`

### Install Strategy

`installStrategy: 'download'` — the provisioner checks if the binary exists and version matches before downloading. Persistent VMs with agentsh already installed skip the download automatically.

### Policy

Converted from the standalone project's `default.yaml` as a complete standalone `PolicyDefinition` (like the runloop adapter). This is necessary because exe.dev's policy diverges significantly from `agentDefault()` — particularly the network rules (no LLM providers, no GitHub/GitLab, no CDNs; only package registries and localhost).

**Note on `approve` decisions:** The reference YAML uses `approve` for credential access (SSH keys, AWS creds, cloud creds, .env files, git credentials) and package installation. The TypeScript `FileRuleSchema` and `CommandRuleSchema` do not support `approve` — only `PackageRuleSchema` does. File and command approve rules are converted to `deny` as the safe fallback, since approvals are disabled in the embedded adapter.

**File rules:**
- Deny dangerous binaries: sudo, su, pkexec, doas, chroot, nsenter, unshare
- Block exe.dev internals: `/usr/bin/shelley`, `/usr/local/bin/shelley`, systemd configs
- Deny credentials: `~/.ssh/**`, `~/.aws/**`, `~/.gcp/**`, `~/.azure/**`, `~/.config/gcloud/**`, `~/.kube/**`, `**/.env`, `**/.env.*`, `~/.git-credentials`, `**/.netrc` (converted from approve to deny)
- Allow workspace: `/root`, `/root/**`, `/workspace`, `/workspace/**` (read, write, create, mkdir, chmod, rename)
- Soft-delete workspace deletes (quarantine via FUSE)
- Allow `/tmp/**` and `/var/tmp/**` (full access)
- Read-only system paths: `/usr/**`, `/lib/**`, `/lib64/**`, `/bin/**`, `/sbin/**`
- Device writes: `/dev/null`, `/dev/zero`, `/dev/tty`, `/dev/pts/**`, `/dev/urandom`, `/dev/random`, `/dev/shm/**`
- Deny sensitive /etc: shadow, gshadow, sudoers
- Minimal `/etc` read: hosts, resolv.conf, CA certs, localtime, timezone, ld.so.cache, ld.so.preload, ld.so.conf, ld.so.nohwcap, nsswitch.conf, passwd, group, fuse.conf, gai.conf
- `/proc/self/**` and `/proc/thread-self/**` read
- Read-only package caches: `~/.npm/**`, `~/.cache/**`, `~/.cargo/**`, `/root/.npm/**`, `/root/.cache/**`, `/root/.cargo/**`
- agentsh runtime: `/var/lib/agentsh/**`, `/var/log/agentsh/**`
- Deny secrets: `**/.env`, `**/credentials*`, `**/*.pem`, `**/*.key`, `~/.ssh/**`, `/proc/*/environ`
- Deny shell config writes: `~/.bashrc`, `~/.zshrc`, `~/.profile`, etc.
- Deny docker socket, credential stores
- Deny `/proc/**`, `/sys/**` writes
- Default deny `**`

**Network rules:**
- Allow localhost: `127.0.0.1/32`, `::1/128`
- Allow package registries: npmjs.org (443), pypi.org + files.pythonhosted.org (443), crates.io + static.crates.io (443), proxy.golang.org + sum.golang.org (443)
- Block cloud metadata: `169.254.169.254/32`, `100.100.100.200/32`
- Block private networks: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`
- Default deny: `*`

**Command rules:**
- Allow safe commands: bash, sh, ls, cat, head, tail, grep, find, wc, sort, uniq, diff, pwd, echo, date, which, etc.
- Allow dev tools: git, node, npm, python, pip, cargo, go, make, etc.
- Allow network tools: curl, wget (network filtering enforced separately)
- Allow-all catch-all: `*` (file + network rules are the real enforcement)
- Deny raw network tools: nc, netcat, ncat, socat, telnet
- Deny system admin: shutdown, reboot, systemctl, service, mount, umount, dd, kill, killall, pkill
- Deny privilege escalation: sudo, su, doas, chroot, nsenter, unshare
- Deny system package managers: apt, apt-get, yum, dnf, brew
- Deny exe.dev interference: shelley, iptables, ip6tables, nft, tc, ip

**Environment policy:**
- Allow: PATH, HOME, USER, SHELL, LANG, LC_*, TERM, TZ, PWD, OLDPWD, SHLVL, _, NODE_ENV, NODE_PATH, NPM_*, PYTHONPATH, VIRTUAL_ENV, PIP_*, GIT_*, AGENTSH_*, HTTP_PROXY, HTTPS_PROXY, NO_PROXY
- Deny: AWS_*, AZURE_*, GCP_*, GOOGLE_*, OPENAI_API_KEY, ANTHROPIC_API_KEY, DATABASE_URL, DB_*, SECRET_*, PASSWORD*, PRIVATE_*, API_KEY*, TOKEN*
- `blockIteration: true`, `maxBytes: 65536`, `maxKeys: 100`

**Signal rules** (same as agentDefault):
- Allow self, children
- Allow safe session signals (SIGTERM, SIGINT, SIGHUP, SIGUSR1, SIGUSR2)
- Audit parent signals
- Deny external fatal signals, deny system signals

**Unix socket rules** (same as agentDefault):
- Allow docker socket connect
- Deny system sockets

**Resource limits** (policy-level, more conservative than agentDefault):
- `maxMemoryMb: 2048` (vs agentDefault 8192)
- `cpuQuotaPercent: 50` (vs agentDefault 100)
- `pidsMax: 100` (vs agentDefault 500)
- `commandTimeout: '5m'` (vs agentDefault 15m)
- `sessionTimeout: '1h'` (vs agentDefault 12h)
- `idleTimeout: '15m'` (vs agentDefault 30m)

**Audit settings** (stricter than agentDefault):
- `logAllowed: true` (agentDefault: false)
- `logDenied: true`
- `logApproved: true`
- `includeStdout: true` (agentDefault: false)
- `includeStderr: true`

### Server Config

Converted from the standalone project's `config.yaml`:

- **gRPC**: `127.0.0.1:9090`
- **Server timeouts**: read 30s, write 60s, max request 10MB
- **Logging**: info level, text format, stderr
- **Sessions**: 100 max, 1h default timeout, 15m idle, 5m cleanup
- **Audit**: enabled, SQLite at `/var/lib/agentsh/events.db`
- **sandboxLimits** (server-level): `maxMemoryMb: 4096`, `maxCpuPercent: 100`, `maxProcesses: 256` — these are the outer server-level bounds, distinct from the policy-level resourceLimits
- **allowDegraded: false** — exe.dev has full kernel capabilities; do not degrade
- **FUSE**: enabled, deferred mode, marker file `/tmp/.agentsh-fuse-enabled`, enable command `['/bin/chmod', '666', '/dev/fuse']`
- **Network**: intercept all, proxy on auto port (`127.0.0.1:0`)
- **Seccomp**: `execve: false` (ptrace handles execve; MUST remain false), `fileMonitor: { enabled: true, enforceWithoutFuse: true }`
- **Ptrace**: enabled, trace `execve: true`, `file: false`, `network: false`, `signal: false`, performance `seccompPrefilter: true`
- **Cgroups**: enabled
- **Unix sockets**: enabled
- **Landlock**: not specified in serverConfig (auto-derived by agentsh from the policy; `ServerConfigOpts` has no landlock field)
- **DLP**: redact mode, standard patterns (email, phone, credit_card, ssn, api_keys) + custom patterns (OpenAI, Anthropic, AWS, GitHub PAT/OAuth, JWT, private keys, Slack tokens)
- **Proxy**: embedded mode, port 0 (auto), providers: Anthropic + OpenAI
- **envInject**: `BASH_ENV: /usr/lib/agentsh/bash_startup.sh`
- **Approvals**: disabled
- **Metrics**: `/metrics`
- **Health**: `/health`, readiness `/ready`
- **Development**: `disableAuth: true`, `verboseErrors: true`

## Usage Example

```typescript
import { secureSandbox } from '@agentsh/secure-sandbox';
import { exe, exeDefaults } from '@agentsh/secure-sandbox/adapters/exe';

// VM already created: ssh exe.dev new --name=my-vm --image=ubuntu:22.04
const adapter = exe('my-vm');
const sandbox = await secureSandbox(adapter, exeDefaults());

const result = await sandbox.exec('echo hello');
console.log(result.stdout); // "hello"

// stop() is a no-op — exe.dev VMs are persistent.
// Destroy VM externally: ssh exe.dev rm my-vm
await sandbox.stop();
```

## Testing

Unit tests mock the SSH layer (child_process.exec) to verify:
- Command construction and shell escaping
- Base64 file write/read
- Detached process handling
- Error extraction from SSH failures
- sudo/cwd/env option handling
- stderr noise filtering (landlock/ptrace/agentsh prefixes stripped)
- stop() is a no-op
- fileExists() returns boolean from `test -f`

---

## Addendum — 2026-04-07 (agentsh v0.17.0 upgrade)

Three issues surfaced during the v0.17.0 bump and were fixed at the adapter / runner / serializer layers. The original design above is preserved as historical intent; current behavior differs where noted.

### 1. PTY forcing on the inner SSH hop

**Symptom.** Exit codes came back as 0 even on failure; stderr was merged into stdout; `\r` characters appeared in captured output.

**Root cause.** The exe.dev gateway always allocates a PTY for the inner `ssh <vmName> ...` hop, regardless of `-T` / `-o RequestTTY=no` on the outer hop (both are rejected: the gateway parses its first argument as a VM name, so `ssh -T vm` becomes "VM '-T' not found"). With a PTY on the inner hop, stderr and stdout are merged onto the same tty, and exit codes are lost unless surfaced in-band.

**Fix (`src/adapters/exe.ts`).** Every command is now wrapped in a base64 marker-protocol script built by `buildWrapper()`. The user command is base64-encoded into `__CMD__`, decoded inside the wrapper, eval'd in a subshell so its exit code can be captured via `$?`, and stdout/stderr are redirected to temp files. The wrapper then prints three sentinel markers — `__AGENTSH_EXE_OUT__<b64>`, `__AGENTSH_EXE_ERR__<b64>`, `__AGENTSH_EXE_EXIT__=<code>` — which `parseWrappedOutput()` extracts and decodes. The entire round-trip survives PTY mangling because only printable ASCII crosses the terminal.

**Why subshell, not command group.** An earlier prototype used `{ eval ...; }` but command groups run in the current shell, so `exit 42` from user code killed the wrapper before the markers could print. Switching to `( eval ...; )` runs the user command in a subshell and preserves the exit code in `$?` for the parent wrapper to capture.

**Fallback.** If the wrapper never runs (SSH/network error), `parseWrappedOutput()` returns null and the adapter surfaces the raw gateway output plus a non-zero exit code so callers notice the failure instead of silently parsing garbage.

### 2. `opts.sudo` is now elided unconditionally

**Symptom.** `provision.ts` calls `adapter.exec('install', ..., { sudo: true })` for the binary install step. On exe.dev this failed with `bash: line 1: sudo: command not found`.

**Root cause.** exe.dev VMs always SSH in as root, AND the default `ubuntu:22.04` image ships with no `sudo` binary at all. The `{ sudo: true }` hint is both redundant (we already have the privileges) and actively broken (there's nothing to call).

**Fix.** The adapter's `exec()` drops the sudo prefix unconditionally. A unit test (`drops sudo prefix because exe.dev VMs are always root`) guards against regression.

### 3. curl pre-install in the e2e runner

**Symptom.** Agentsh provisioning failed at the `download` phase because neither `curl` nor `wget` was available.

**Root cause.** Default `ubuntu:22.04` on exe.dev has no HTTP client, so `installStrategy: 'download'` had nothing to fetch the tarball with.

**Fix (`src/e2e/exe-e2e-runner.ts`).** `ensureCurlInstalled(vmName)` runs `apt-get update && apt-get install -y curl ca-certificates` after `waitForSSH`. The install is idempotent, so it's safe on both fresh and reused VMs. Users who run the adapter outside the e2e runner must install curl themselves, or use a pre-baked image, or switch to `installStrategy: 'preinstalled'`.

### 4. `seccomp.execve` schema change (not exe.dev-specific, but observed here first)

**Symptom.** Agentsh server failed to parse `/etc/agentsh/config.yml`: `line 33: cannot unmarshal !!bool false into config.ExecveConfig`.

**Root cause.** agentsh v0.17.0 turned `seccomp.execve` from a bare bool into an `ExecveConfig` struct. Adapters that set `seccompDetails.execve` (exe.dev, sprites) emitted the old bare-bool form and could no longer start the server. `ptrace.trace.execve` is unaffected — it's still a bool.

**Fix (`src/core/config.ts`).** `generateServerConfig` now wraps `seccompDetails.execve` as `{ enabled: bool }` at serialization time. The `ServerConfigOpts` caller API is unchanged — still `execve?: boolean` — so no adapter call sites had to move.
