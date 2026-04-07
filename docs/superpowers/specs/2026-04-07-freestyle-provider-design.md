# Freestyle Provider Adapter Design

## Overview

Add freestyle.sh as a sandbox provider in `@agentsh/secure-sandbox`. Freestyle provides Firecracker-backed Linux VMs (Ubuntu 22.04) accessed via a typed TypeScript SDK (`freestyle-sandboxes`). Unlike adapters that wrap an arbitrary shell transport, Freestyle offers both a rich exec API (`vm.exec({command, timeoutMs})`) and a first-class filesystem API (`vm.fs.readTextFile` / `writeTextFile` / `exists`).

Freestyle also has a **declarative VM provisioning model** (`VmSpec` builder) that lets callers bake agentsh into the VM image at snapshot time. This is a significant differentiator from all other providers we support, so in addition to the usual `freestyle(vm)` / `freestyleDefaults()` pair, this spec also introduces a `configureFreestyleSpec(spec)` helper that sets up the agentsh install + config systemd services on a `VmSpec`.

The policy and server config are ported from the reference project at `/home/eran/work/canyonroad/agentsh-freestyle` (`config.yaml`, `default.yaml`, `agentsh-startup.sh`, `src/vm-agentsh.ts`). Two Freestyle-specific constraints drive the server config:

1. **Freestyle kernels lack Yama.** Agentsh's seccomp file_monitor relies on `process_vm_readv`, which Yama gates; the reference config explicitly disables `seccomp.file_monitor.enabled` and notes it conflicts with FUSE without Yama.
2. **`/dev/fuse` has mode 600 by default.** FUSE must be enabled in **deferred mode** with `deferred_enable_command: ['sudo', '/bin/chmod', '666', '/dev/fuse']`, guarded by a marker file.

Both constraints mean Freestyle runs with **`allow_degraded: true`** — agentsh's runtime detection will settle into **`minimal`** security mode because Landlock isn't present and file_monitor is disabled. This is a conscious, documented choice (not a bug), so the adapter defaults mirror it. Callers who want to fail-fast on degraded mode on other kernels should override with `minimumSecurityMode: 'landlock'`; on Freestyle that override will correctly error at provisioning time.

## Files

| File | Action | Purpose |
|------|--------|---------|
| `src/adapters/freestyle.ts` | Create | Adapter factory + defaults + VmSpec helper |
| `src/adapters/index.ts` | Edit | Add `freestyle`, `freestyleDefaults`, `configureFreestyleSpec` exports |
| `src/adapters/adapters.test.ts` | Edit | Add `freestyle adapter` describe block + include `freestyleDefaults` in the provider-defaults matrix |
| `src/e2e/freestyle-e2e-runner.ts` | Create | Live E2E runner (pattern matches `runloop-e2e-runner.ts`) |
| `package.json` | Edit | Add `./adapters/freestyle` export path, `freestyle-sandboxes` optional peer dep, `test:e2e:freestyle` script |
| `README.md` | Edit | Add Freestyle to supported-platforms table, primary-enforcement table, provider bullet in the intro paragraph, and a usage snippet in the examples block |

## Adapter: `freestyle(vm: any): SandboxAdapter`

### Input

Accepts a `Vm` instance from `freestyle-sandboxes`:

```ts
import { freestyle as freestyleClient } from 'freestyle-sandboxes';
const fs = freestyleClient({ apiKey: process.env.FREESTYLE_API_KEY });
const { vm } = await fs.vms.create(someSpec);
const adapter = freestyle(vm);
```

The parameter is typed as `any` to keep `freestyle-sandboxes` as an **optional** peer dep (same pattern we already use for runloop / cloudflare / blaxel / sprites). The actual shape the adapter relies on:

- `vm.exec({ command: string, timeoutMs?: number }): Promise<{ stdout?: string|null, stderr?: string|null, statusCode?: number|null }>`
- `vm.fs.writeTextFile(path: string, content: string): Promise<void>`
- `vm.fs.readTextFile(path: string): Promise<string>`
- `vm.fs.exists(path: string): Promise<boolean>`
- `vm.stop(): Promise<unknown>` (graceful stop via the Freestyle API)

### Methods

- **`exec(cmd, args, opts)`** — Composes an `sh -c` string via `envPrefix(opts.env) + shellEscape(cmd, args)`, optionally wraps in `cd <cwd> && ...`, and routes through `vm.exec({command: 'sh -c ' + escapedCmd, timeoutMs})`. Supports:
  - `sudo`: prefix `sudo ` when requested. Unlike exe.dev, Freestyle VMs ship with `sudo` installed (the reference `configureSnapshotSpec` explicitly includes `sudo` in `aptDeps` and adds `NOPASSWD` entries for agentsh), so the hint stays active.
  - `cwd`: wrap in `cd '<escaped>' && <cmd>`.
  - `env`: preprend `KEY=value` pairs via `envPrefix`.
  - `detached`: `nohup <cmd> > /dev/null 2>&1 &` fire-and-forget; returns immediately with `exitCode: 0`.
  - Normalizes the Freestyle response: treats all of `stdout` / `stderr` / `statusCode` as nullable and maps `statusCode ?? 0` to `exitCode`.
  - Catches SDK exceptions and surfaces them as `{stdout: '', stderr: err.message, exitCode: 1}` so the provisioner sees a deterministic failure rather than an uncaught throw.

- **`writeFile(path, content)`** — Uses `vm.fs.writeTextFile(path, content.toString('utf-8'))` when `content` is a string; uses `vm.fs.writeFile(path, buf)` when a `Buffer` is passed. This avoids the base64+exec dance used by cloudflare/modal/sprites/exe.

- **`readFile(path)`** — Uses `vm.fs.readTextFile(path)`.

- **`stop()`** — Calls `await vm.stop()`. Freestyle VMs *can* be persistent (snapshots, suspended VMs), but the adapter's responsibility matches the convention set by runloop/daytona/e2b/cloudflare: stop the VM gracefully so the caller's resource is released. If the caller wants the VM to survive, they skip calling `sandbox.stop()` or take a snapshot first.

- **`fileExists(path)`** — Uses `vm.fs.exists(path)`. This enables fast detection of pre-installed agentsh when `configureFreestyleSpec` has baked it into the VM (matches the `exe` adapter pattern).

### Why use `vm.fs.*` instead of exec-based base64

Every other adapter (exe, cloudflare, modal, sprites) implements `writeFile` as `printf '%s' '<b64>' | base64 -d > 'path'`. That pattern exists because those providers only expose `exec`. Freestyle exposes a typed filesystem API, so using it is strictly better:

- No shell-escaping edge cases or path traversal surface.
- No base64 round-trip cost for every config/policy file written during provisioning.
- Clearer stack traces when something goes wrong.
- Binary files (if we ever start writing the agentsh tarball via `upload`) work naturally with the Buffer overload.

## Defaults: `freestyleDefaults(): Partial<SecureConfig>`

### Install Strategy

`installStrategy: 'download'` — matches runloop/exe. The provisioner checks if `/usr/local/bin/agentsh` exists via `fileExists` and, if not, downloads the v0.17.0 tarball from GitHub inside the VM. When `configureFreestyleSpec` is used to bake agentsh into the VM at spec time, the fast-path detection kicks in and the download is skipped automatically.

The reference project uses a `.deb` package installed via systemd oneshot (`dpkg -i agentsh_0.16.9_linux_amd64.deb`); our provisioner uses the tarball form because it's the lowest-common-denominator install path already implemented in `provision.ts`. Users who need .deb semantics (systemd unit files, group creation, sudoers) should use `configureFreestyleSpec` which replicates the .deb bootstrap.

### Server Config

Translated from `agentsh-freestyle/config.yaml` into `ServerConfigOpts`:

- **gRPC**: `127.0.0.1:9090`
- **Server timeouts**: read 30s, write 60s, max request 10MB
- **Logging**: info level, text format, stderr
- **Sessions**: 100 max, 1h default, 15m idle, 5m cleanup
- **Audit**: enabled, SQLite at `/var/lib/agentsh/events.db`
- **sandboxLimits**: `maxMemoryMb: 4096`, `maxCpuPercent: 100`, `maxProcesses: 256`
- **`allowDegraded: true`** — Freestyle runs in degraded mode by design (no Yama, no Landlock, file_monitor disabled). This is the key differentiator from `exeDefaults()`, which sets `allowDegraded: false`.
- **FUSE**: deferred, marker file `/tmp/.agentsh-fuse-enabled`, enable command `['sudo', '/bin/chmod', '666', '/dev/fuse']` — note the explicit `sudo` prefix (exe.dev uses `['/bin/chmod', ...]` because VMs there are always root).
- **Network**: intercept all, proxy on auto port (`127.0.0.1:0`)
- **Seccomp**: `execve: true` (per-command wrapper via agentsh-unixwrap), `fileMonitor: { enabled: false, enforceWithoutFuse: false }` — the critical Freestyle-specific setting. Once Yama is available in Freestyle kernels, this can be flipped to `enabled: true`.
- **Cgroups**: enabled
- **Unix sockets**: enabled
- **envInject**: `BASH_ENV: /usr/lib/agentsh/bash_startup.sh` (shell shim hook — consistent with exe.dev)
- **DLP**: redact mode, standard patterns (email, phone, credit_card, ssn, api_keys) + custom patterns (OpenAI, Anthropic, AWS, GitHub PAT/OAuth, JWT, private keys, Slack tokens) — identical to the exe.dev / freestyle reference.
- **Proxy**: embedded mode, port 0 (auto), providers: Anthropic + OpenAI
- **Approvals**: disabled
- **Metrics**: `/metrics`
- **Health**: `/health`, readiness `/ready`
- **Development**: `disableAuth: true`, `verboseErrors: false` (matches reference; exe.dev uses `true`)

### Policy

Translated from `agentsh-freestyle/default.yaml` into a complete standalone `PolicyDefinition` (same approach as runloop and exe.dev). The policy differs from `agentDefault()` in several Freestyle-specific ways, so reusing the preset isn't appropriate.

**Schema translation note.** The reference YAML uses `decision: approve` for SSH keys, AWS/cloud creds, `.env` files, git credentials, and package installation. The TypeScript `FileRuleSchema` and `CommandRuleSchema` do not support `approve` — only `PackageRuleSchema` does. File and command `approve` rules are converted to `deny` (the safe fallback), matching what runloop/exe.dev already do. The rationale: approvals require an interactive callback loop that isn't wired up in embedded adapter usage, so falling back to deny is the conservative correct behaviour.

**File rules** (order matters — first match wins):
- Deny privilege escalation binaries: `/usr/bin/sudo`, `/usr/bin/su`, `/usr/bin/pkexec`, `/usr/bin/doas`, `/bin/su`, `/usr/sbin/chroot`, `/usr/bin/nsenter`, `/usr/bin/unshare`
- Deny Freestyle infrastructure: `/usr/bin/envd` (environment daemon), `/usr/bin/socat`, `/etc/systemd/**`, `/run/systemd/**` — this is the Freestyle-unique block, missing from other providers.
- Deny credentials (converted from approve): `/home/user/.ssh/**`, `/root/.ssh/**`, `/home/user/.aws/**`, `/root/.aws/**`, `/home/user/.gcloud/**`, `/home/user/.azure/**`, `/home/user/.config/gcloud/**`, `/home/user/.kube/**`, `**/.env`, `**/.env.*`, `/home/user/.git-credentials`, `**/.netrc`
- Allow workspace: `/home/user`, `/home/user/**`, `/workspace`, `/workspace/**` (read, write, create, open, stat, list, readlink, mkdir, chmod, rename)
- Soft-delete workspace deletes (quarantine via FUSE soft-delete)
- Allow `/tmp/**` and `/var/tmp/**` (full access)
- Read-only system paths: `/usr/**`, `/lib/**`, `/lib64/**`, `/bin/**`, `/sbin/**`
- Allow essential device files: `/dev/null`, `/dev/zero`, `/dev/urandom`, `/dev/random`, `/dev/stdin`, `/dev/stdout`, `/dev/stderr`, `/dev/fd/**`, `/dev/pts/**`, `/dev/tty` (read, write, open, stat)
- Read-only package caches: `/home/user/.npm/**`, `/home/user/.cache/**`, `/home/user/.cargo/**`, `/root/.npm/**`, `/root/.cache/**`, `/root/.cargo/**`
- Deny sensitive `/etc`: shadow, gshadow, sudoers
- Minimal `/etc` read: hosts, resolv.conf, SSL certs, CA certs, localtime, timezone, ld.so.cache, ld.so.preload, ld.so.nohwcap, nsswitch.conf, passwd, group, fuse.conf
- `/proc/self/**` and `/proc/thread-self/**` read
- agentsh runtime: `/var/lib/agentsh/**`, `/var/log/agentsh/**` (read, write)
- Deny `/proc/**`, `/sys/**` writes
- Default deny `**`

**Workspace root.** The reference uses `${PROJECT_ROOT}` (substituted to `/home/user` at server startup). We hard-code `/home/user` since secure-sandbox doesn't thread the variable through, and `/home/user` matches Freestyle's default VM layout. The adapter's `workspace` config defaults accordingly.

**Network rules** (matches reference, minus `${PROJECT_ROOT}` templating):
- Allow localhost: `127.0.0.1/32`, `::1/128` (agentsh server + embedded LLM proxy)
- Allow package registries: `registry.npmjs.org` (443); `pypi.org` + `files.pythonhosted.org` (443); `crates.io` + `static.crates.io` (443); `proxy.golang.org` + `sum.golang.org` (443)
- Block cloud metadata: `169.254.169.254/32`, `100.100.100.200/32`
- Block private networks: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`
- Block Freestyle internal events (`192.0.2.0/24` — TEST-NET-1 range used by Freestyle for internal services per reference config)
- Block `evil.com` / `*.evil.com` (example test fixtures kept from reference)
- Default deny `*`

**Command rules**:
- Allow network tools: `curl`, `wget` (network rules handle domain policy)
- Allow safe commands: `bash`, `sh`, `/bin/bash`, `/bin/sh`, `/usr/bin/bash`, `/usr/bin/sh`, `ls`, `cat`, `head`, `tail`, `grep`, `find`, `wc`, `sort`, `uniq`, `diff`, `pwd`, `echo`, `date`, `which`, plus `env`, `printenv`, `true`, `false`, `test`, `[`, `expr`, `seq`, `sh.real`, `bash.real`
- Allow dev tools: `git`, `node`, `npm`, `python`, `python3`, `pip`, `pip3`, `cargo`, `go`, `make`
- Deny raw network tools (reverse-shell prevention): `nc`, `netcat`, `ncat`, `socat`, `telnet`, `ssh`, `scp`, `rsync`
- Deny system administration: `shutdown`, `reboot`, `systemctl`, `service`, `mount`, `umount`, `dd`, `fdisk`, `mkfs`, `kill`, `killall`, `pkill`
- Deny privilege escalation: `sudo`, `su`, `doas`, `chroot`, `nsenter`, `unshare`
- Deny Freestyle interference: `socat`, `envd`, `iptables`, `ip6tables`, `nft`, `tc`, `ip`
- Note: `rm -r` / `rm --recursive` is an `args_patterns` rule in the reference YAML that the TS schema does not model as granularly. We drop that rule and rely on the file-level deletion quarantine (soft-delete) in the workspace instead — the workspace deny falls through to soft_delete, and outside the workspace recursive deletion is already blocked by the default deny.
- Allow `*` catch-all — file + network rules are the real enforcement.

**Environment policy**:
- Allow: `PATH`, `HOME`, `USER`, `SHELL`, `LANG`, `LANG_*`, `LC_*`, `TERM`, `TERM_*`, `TZ`, `PWD`, `OLDPWD`, `SHLVL`, `_`, `NODE_ENV`, `NODE_PATH`, `NPM_*`, `PYTHONPATH`, `VIRTUAL_ENV`, `PIP_*`, `GIT_*`, `AGENTSH_*`, `HTTP_PROXY`, `HTTPS_PROXY`, `http_proxy`, `https_proxy`, `NO_PROXY`, `no_proxy`
- Deny: `AWS_*`, `AZURE_*`, `GCP_*`, `GOOGLE_*`, `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `DATABASE_URL`, `DB_*`, `SECRET_*`, `PASSWORD*`, `PRIVATE_*`, `API_KEY*`, `TOKEN*`
- `blockIteration: true`, `maxBytes: 65536`, `maxKeys: 100`

**Signal rules** (same pattern as exe.dev / agentDefault):
- Allow self, children
- Allow safe session signals (SIGTERM, SIGINT, SIGHUP, SIGUSR1, SIGUSR2)
- Audit parent signals
- Deny external fatal signals, deny system signals

**Unix socket rules**:
- Deny `/var/run/**` connect/bind/listen/sendto

**Resource limits** (policy-level — more conservative than sandbox-level serverConfig limits):
- `maxMemoryMb: 2048` (vs server 4096)
- `cpuQuotaPercent: 50`
- `pidsMax: 100`
- `commandTimeout: '5m'`, `sessionTimeout: '1h'`, `idleTimeout: '15m'`

**Audit settings** (stricter than `agentDefault`):
- `logAllowed: true`, `logDenied: true`, `logApproved: true`, `includeStdout: true`, `includeStderr: true`

### Workspace

`workspace: '/home/user'` — matches the Freestyle VM default user home and the reference config's `${PROJECT_ROOT}` substitution. Callers can override via `secureSandbox(adapter, { ...freestyleDefaults(), workspace: '/workspace' })`.

## VmSpec Helper: `configureFreestyleSpec(spec, opts?)`

Freestyle is the only provider where the caller builds a declarative VM spec before creating the VM. To let callers opt into a pre-baked agentsh install (much faster provisioning), this helper mutates an incoming `VmSpec` to include everything needed for agentsh to start at boot.

### Signature

```ts
export function configureFreestyleSpec(
  spec: any,  // VmSpec — typed as any to keep peer dep optional
  opts?: { agentshVersion?: string; policyYaml?: string; configYaml?: string },
): any;
```

### Behaviour

Ports the reference project's `VmAgentsh.configureSnapshotSpec` + `configureSpec` into a single function call:

1. **aptDeps**: `ca-certificates`, `curl`, `jq`, `libseccomp2`, `sudo`, `fuse3`, `python3`, `file`, `sqlite3` (matches reference, minus `sudo` NOPASSWD tweaks which we do via `additionalFiles`).
2. **additionalFiles**:
   - `/opt/install-agentsh.sh` — bash script that downloads `agentsh_<version>_linux_amd64.tar.gz` from GitHub, extracts, installs `/usr/local/bin/agentsh`, `/usr/bin/agentsh-shell-shim`, `/usr/local/bin/agentsh-unixwrap`, creates agentsh directories with correct permissions, appends NOPASSWD sudoers entries for agentsh and `/dev/fuse` chmod, enables `user_allow_other` in `/etc/fuse.conf`. Version defaults to `AGENTSH_VERSION` constant (`0.17.0`, matching `scripts/build-sandbox-images.ts`).
   - `/etc/agentsh/config.yml` — serialized agentsh server config. When `opts.configYaml` is provided, use it verbatim; otherwise derive from `freestyleDefaults().serverConfig` using the existing `generateServerConfig()` serializer. This keeps the baked config in sync with the runtime defaults.
   - `/etc/agentsh/policies/default.yaml` — serialized policy. When `opts.policyYaml` is provided, use it verbatim; otherwise derive from `freestyleDefaults().policy` using `serializePolicy()`.
   - `/opt/agentsh-startup.sh` — startup script copied from the reference (`sudo /bin/chmod 600 /dev/fuse`, start agentsh server, wait for health, install shell shim). Embedded as a string literal in the adapter file.
   - `/etc/environment` — injects `AGENTSH_SERVER=http://127.0.0.1:18080` and `AGENTSH_SHIM_FORCE=1`.
3. **systemdService (install, oneshot)**:
   ```ts
   { name: 'install-agentsh', mode: 'oneshot', exec: ['bash /opt/install-agentsh.sh'], wantedBy: ['multi-user.target'] }
   ```
4. **systemdService (server)**:
   ```ts
   {
     name: 'agentsh',
     mode: 'service',
     exec: ['bash /opt/agentsh-startup.sh'],
     env: { AGENTSH_SERVER: 'http://127.0.0.1:18080', AGENTSH_SHIM_FORCE: '1' },
     after: ['install-agentsh.service'],
     wantedBy: ['multi-user.target'],
   }
   ```

### Usage pattern

```ts
import { freestyle as freestyleClient, VmSpec } from 'freestyle-sandboxes';
import { freestyle, freestyleDefaults, configureFreestyleSpec } from '@agentsh/secure-sandbox/adapters/freestyle';
import { secureSandbox } from '@agentsh/secure-sandbox';

const fs = freestyleClient({ apiKey: process.env.FREESTYLE_API_KEY });

// Bake agentsh into a snapshot
const spec = configureFreestyleSpec(new VmSpec().snapshot());
const { vm } = await fs.vms.create(spec);

// Fast-path: agentsh already installed, fileExists() detects it
const sandbox = await secureSandbox(freestyle(vm), {
  ...freestyleDefaults(),
  installStrategy: 'preinstalled',
});

await sandbox.exec('echo hello');
await sandbox.stop();
```

Callers who don't want a pre-baked image can skip `configureFreestyleSpec` entirely and rely on `installStrategy: 'download'` (the default), which installs agentsh at provisioning time. That path is slower on cold boot but requires zero image prep.

## Usage Example (minimal)

```typescript
import { freestyle as freestyleClient, VmSpec } from 'freestyle-sandboxes';
import { secureSandbox } from '@agentsh/secure-sandbox';
import { freestyle, freestyleDefaults } from '@agentsh/secure-sandbox/adapters/freestyle';

const fs = freestyleClient({ apiKey: process.env.FREESTYLE_API_KEY });
const { vm } = await fs.vms.create({ spec: new VmSpec() });

const sandbox = await secureSandbox(freestyle(vm), freestyleDefaults());

const result = await sandbox.exec('echo hello');
console.log(result.stdout); // "hello"

await sandbox.stop();
```

## Testing

### Unit tests (`src/adapters/adapters.test.ts`)

Follow the existing `describe('runloop adapter', ...)` and `describe('modal adapter', ...)` patterns. Add a `freestyle adapter` describe block with:

- **exec mapping**: mock `vm.exec` returning `{stdout: 'out', stderr: '', statusCode: 0}`, verify the adapter wraps with `sh -c`, escapes args, returns `{stdout: 'out', stderr: '', exitCode: 0}`.
- **sudo prefix**: `{sudo: true}` prepends `sudo ` to the command.
- **cwd wrapper**: `{cwd: '/tmp'}` wraps as `cd '/tmp' && ...`.
- **env prefix**: `{env: {FOO: 'bar'}}` emits `FOO=bar <cmd>`.
- **detached**: `{detached: true}` fires `nohup ... &` without awaiting and returns `exitCode: 0`.
- **statusCode normalization**: `vm.exec` returning `{statusCode: null}` and `{statusCode: 0}` both map to `exitCode: 0`; `{statusCode: 2}` maps to `exitCode: 2`; missing `stdout`/`stderr` are coerced to `''`.
- **SDK throw**: `vm.exec` rejecting surfaces as `{exitCode: 1, stderr: errMsg}`, not an uncaught throw.
- **writeFile uses `vm.fs.writeTextFile`**: assert `vm.fs.writeTextFile` is called with the exact path and content; `vm.exec` is never called during `writeFile`.
- **readFile uses `vm.fs.readTextFile`**: same pattern.
- **fileExists uses `vm.fs.exists`**: returns the value directly.
- **stop calls `vm.stop`**.

Also add `{ name: 'freestyleDefaults', fn: freestyleDefaults }` to the provider-defaults matrix at `adapters.test.ts:846` so that:
- The policy validates against `PolicyDefinitionSchema`.
- The policy serializes to valid YAML.

And add freestyle-specific assertion tests mirroring the runloop examples (`runloopDefaults denies credential paths`, etc.):
- `freestyleDefaults includes /home/user workspace paths`
- `freestyleDefaults blocks Freestyle infrastructure (/usr/bin/envd, /etc/systemd/**)`
- `freestyleDefaults uses allowDegraded: true and disables seccomp file_monitor`

### E2E runner (`src/e2e/freestyle-e2e-runner.ts`)

Mirror `src/e2e/runloop-e2e-runner.ts`:

1. Load `.env.e2e` via dotenv (already set up in repo).
2. Skip (exit 0 with a log message) if `FREESTYLE_API_KEY` is missing.
3. Skip if `require.resolve('freestyle-sandboxes')` fails (optional peer dep).
4. Create a VM using `fs.vms.create(configureFreestyleSpec(new VmSpec().snapshot()))` so agentsh is already baked in.
5. Wait for the `agentsh.service` systemd unit to become ready (poll `vm.exec({command: 'curl -sf http://127.0.0.1:18080/health'})` for up to 60s).
6. Wrap with `secureSandbox(freestyle(vm), { ...freestyleDefaults(), installStrategy: 'preinstalled' })`.
7. Run the standard integration probe set used by other runners (read workspace, write workspace, deny `~/.ssh`, block curl to an unlisted domain, allow curl to npm registry).
8. `await sandbox.stop()` then `await vm.delete({vmId: vm.vmId})` to clean up.

Add `"test:e2e:freestyle": "npx tsx src/e2e/freestyle-e2e-runner.ts"` to `package.json` scripts.

## README updates

- **Intro paragraph** (`README.md:3`): add `[Freestyle](https://freestyle.sh)` to the provider list and a matching new column in the protections table.
- **Supported Platforms table** (`README.md:113`): add a `Freestyle` column.
- **Primary Enforcement table** (`README.md:124`): add `| [**Freestyle**](https://freestyle.sh) | seccomp (wrapper) + network proxy + FUSE (deferred) + cgroups | minimal |` — the `minimal` security mode reflects the `allow_degraded` posture documented above. This is the first provider we ship at `minimal` mode, so add a `> **Freestyle:** …` callout below the Modal/exe.dev notes explaining why (no Yama, file_monitor disabled, FUSE needs a deferred enable step) and what that buys (per-command seccomp wrapping + network/DLP proxy + FUSE soft-delete + cgroups).
- **Usage examples block** (`README.md:142`): add a Freestyle snippet mirroring the Runloop/exe.dev pattern.

## Notes on version skew

The reference project pins agentsh v0.16.9 (and uses the `.deb` package install). Our library now targets v0.17.0 (`scripts/build-sandbox-images.ts:22`). The v0.17.0 upgrade fixed two things that matter here:

1. **`seccomp.execve` schema change.** In v0.16.9 it was a bare bool; in v0.17.0 it became a struct. `generateServerConfig` already wraps `seccompDetails.execve` as `{ enabled: bool }` at serialization time (per the exe.dev addendum in `2026-03-29-exe-dev-provider-design.md`), so the Freestyle adapter inherits that fix for free.
2. **`seccomp.file_monitor`** gained the `enforceWithoutFuse` knob. We set it to `false` explicitly since the whole file_monitor subsystem is disabled for Freestyle.

No other v0.16.9 → v0.17.0 changes affect the Freestyle adapter.
