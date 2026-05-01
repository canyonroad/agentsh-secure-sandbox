# Socket Family Blocking + agentsh v0.19.0

Expose agentsh v0.19.0's per-AF_* socket family blocking through the secure-sandbox TypeScript API, and bump the pinned agentsh version from `0.18.3` to `0.19.0`.

## Context

agentsh v0.19.0 (commit `bcc70677`) adds per-AF_* family blocking on `socket(2)` and `socketpair(2)`, configured under `sandbox.seccomp.blocked_socket_families`. Two enforcement engines (seccomp-bpf primary, ptrace fallback) share the config and emit identical `seccomp_socket_family_blocked` audit events. The motivating CVE class is `socket(AF_<niche>, ...)` as a kernel attack entry point — see [copy.fail](https://copy.fail/#mitigation) for the AF_ALG case.

When the YAML field is unset, agentsh applies a 12-family recommended-default list at `action: errno` (AF_ALG, AF_VSOCK, AF_RDS, AF_TIPC, AF_KCM, AF_X25, AF_AX25, AF_NETROM, AF_ROSE, AF_DECnet, AF_APPLETALK, AF_IPX). Setting the field to `[]` is an explicit opt-out; a non-empty list overrides the defaults.

secure-sandbox currently pins agentsh `0.18.3`, so this feature is unreachable from TS callers and the version pin is one minor behind upstream.

## Scope

| Item | Layer | Files |
|---|---|---|
| `seccompDetails.blockedSocketFamilies` field | Server config | `src/core/config.ts` |
| Tri-state YAML emission (omitted / `[]` / populated) | Server config | `src/core/config.ts` |
| Version bump 0.18.3 → 0.19.0 | Integrity / install | `src/core/integrity.ts`, `src/adapters/freestyle.ts`, `scripts/build-sandbox-images.ts` |
| Tests | Unit | `src/core/config.test.ts`, `src/adapters/adapters.test.ts` |
| README mention | Docs | `README.md` |

Out of scope (deferred): `skillcheck` configuration (the other v0.19.0 feature), `serializePolicy` changes (this is sandbox config, not policy), per-adapter overrides — adapters keep relying on agentsh defaults.

## API surface

`ServerConfigOpts.seccompDetails` gains one optional field:

```typescript
seccompDetails?: {
  execve?: boolean;
  fileMonitor?: { /* unchanged */ };
  blockedSocketFamilies?: Array<{
    family: string;                                          // 'AF_ALG' or numeric string '38'
    action?: 'errno' | 'kill' | 'log' | 'log_and_kill';     // omitted → agentsh defaults to 'errno'
  }>;
};
```

The field is nested under `seccompDetails` for three reasons:
1. Mirrors the agentsh YAML shape (`sandbox.seccomp.blocked_socket_families`).
2. `seccompDetails` already houses `execve` and `fileMonitor` and already implicitly enables seccomp when set — same semantics we want here.
3. No top-level surface to maintain.

### Tri-state semantics (preserved from agentsh)

| Caller passes | YAML emitted | agentsh behavior |
|---|---|---|
| field omitted | `blocked_socket_families` absent | applies 12-family default list at errno |
| `blockedSocketFamilies: []` | `blocked_socket_families: []` | opts out of all family blocking |
| non-empty list | `blocked_socket_families: [...]` | uses the supplied list, overrides defaults |

`action` is optional per-entry in TS. When omitted by the caller, the entry is emitted without an `action` key, and agentsh applies its `errno` default. Validation of family names and action values happens server-side at config-load time — no TS-side allowlist required (kernel adds families rarely; the agentsh table is authoritative).

### Implicit enablement

Existing rule in `generateServerConfig` (around `config.ts:298`): when `seccompDetails` is provided AND `ptrace.enabled` is not true, `sandbox.seccomp.enabled = true`. This rule is unchanged — passing only `blockedSocketFamilies` (without execve/fileMonitor) implicitly enables seccomp. With ptrace enabled, seccomp stays disabled and agentsh's ptrace fallback engine handles family blocking.

## Version bump

Three constants + one test literal + one entry added to `CHECKSUMS`:

- **`src/core/integrity.ts`**:
  - `PINNED_VERSION = '0.19.0'`
  - Add to `CHECKSUMS`: `'0.19.0': { linux_amd64: '04c1b0e958a6e9027fc85d4625bec765e459f191dc16c4c5a04468c867f71d85', linux_arm64: '89cecae90e6511cf96019cca948e3b5142dce329349141eb838979a243dda9cd' }`
  - Older versions retained for callers that pin.
- **`src/adapters/freestyle.ts`**: `AGENTSH_VERSION = '0.19.0'`
- **`scripts/build-sandbox-images.ts`**: `AGENTSH_VERSION = '0.19.0'`
- **`src/adapters/adapters.test.ts:1234`**: update the `'0.18.3'` literal in the install-script assertion to `'0.19.0'`.

Checksums sourced from the v0.19.0 release `checksums.txt`.

## Tests

Add to `src/core/config.test.ts`, mirroring the existing `seccompDetails` test pattern (around lines 282–290):

1. **Default (omitted)** — `seccompDetails: { execve: true }` produces a config with `parsed.sandbox.seccomp.blocked_socket_families` undefined.
2. **Opt-out (`[]`)** — `seccompDetails: { blockedSocketFamilies: [] }` emits `blocked_socket_families: []` (Array.isArray true, length 0). Verifies js-yaml round-trip preserves the empty array.
3. **Populated list** — `seccompDetails: { blockedSocketFamilies: [{ family: 'AF_VSOCK', action: 'log_and_kill' }, { family: 'AF_ALG' }] }` emits the matching YAML with the second entry having no `action` key.
4. **Implicit enablement** — passing only `blockedSocketFamilies` (no execve/fileMonitor) sets `parsed.sandbox.seccomp.enabled = true`.
5. **Ptrace precedence** — with `ptrace: { enabled: true }`, seccomp stays disabled even when `blockedSocketFamilies` is set (existing rule on `config.ts:298`).

## README

Add a short note in the relevant configuration section: secure-sandbox now blocks 12 niche AF_* socket families by default at `EAFNOSUPPORT`. Operators can override via `serverConfig.seccompDetails.blockedSocketFamilies` (full list) or opt out via `[]`. Reference upstream `docs/seccomp.md` for the canonical list and audit event shape.

## Verification

End-to-end:
1. `npm run typecheck` — confirms new field types compile.
2. `npm test` — runs `vitest`, exercising the five new config tests + the bumped adapter assertion.
3. Manual integration (optional, requires a Linux host with seccomp): build with `AGENTSH_VERSION=0.19.0`, configure `seccompDetails.blockedSocketFamilies: [{ family: 'AF_VSOCK', action: 'log' }]`, run a small program that calls `socket(AF_VSOCK, SOCK_STREAM, 0)`, confirm it returns `EAFNOSUPPORT` and a `seccomp_socket_family_blocked` audit event lands.

## Critical files

- `src/core/config.ts` (extend `ServerConfigOpts.seccompDetails`, wire YAML emission)
- `src/core/integrity.ts` (PINNED_VERSION + CHECKSUMS entry)
- `src/adapters/freestyle.ts` (AGENTSH_VERSION constant)
- `scripts/build-sandbox-images.ts` (AGENTSH_VERSION constant)
- `src/core/config.test.ts` (5 new tests)
- `src/adapters/adapters.test.ts:1234` (version literal)
- `README.md` (short note)
