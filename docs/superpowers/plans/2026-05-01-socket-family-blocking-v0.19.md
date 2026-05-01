# Socket Family Blocking + agentsh v0.19.0 — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Expose agentsh v0.19.0's per-AF_* socket family blocking through the secure-sandbox TS API and bump the pinned agentsh version from 0.18.3 to 0.19.0.

**Architecture:** Single seam — extend `ServerConfigOpts.seccompDetails` with `blockedSocketFamilies?: Array<{family, action?}>`. `generateServerConfig` emits it under `sandbox.seccomp.blocked_socket_families` when present. Tri-state semantics (omitted → agentsh defaults; `[]` → opt-out; populated → override) preserved by branching on `!== undefined`. Version bump touches three constants and one test literal.

**Tech Stack:** TypeScript, vitest, js-yaml, zod (unchanged), tsup.

**Spec:** `docs/superpowers/specs/2026-05-01-socket-family-blocking-v0.19-design.md`

---

## File Map

| File | Change |
|---|---|
| `src/core/config.ts` | Extend `ServerConfigOpts.seccompDetails`; add YAML emission branch |
| `src/core/config.test.ts` | 5 new tests at the end of the existing `generateServerConfig` describe block |
| `src/core/integrity.ts` | Bump `PINNED_VERSION`; add `0.19.0` checksum entry |
| `src/adapters/freestyle.ts` | Bump `AGENTSH_VERSION` constant |
| `scripts/build-sandbox-images.ts` | Bump `AGENTSH_VERSION` constant |
| `src/adapters/adapters.test.ts` | Update version literal at line 1234 |
| `README.md` | Short note on default-blocked socket families |

---

## Task 1: Add `blockedSocketFamilies` to `ServerConfigOpts.seccompDetails`

Extend the type only — no emission logic yet. This isolates the type change so the next task can TDD the emission cleanly.

**Files:**
- Modify: `src/core/config.ts:44`

- [ ] **Step 1: Extend the type**

Replace the single line at `src/core/config.ts:44`:

```typescript
seccompDetails?: { execve?: boolean; fileMonitor?: { enabled?: boolean; enforceWithoutFuse?: boolean; interceptMetadata?: boolean; openatEmulation?: boolean; blockIoUring?: boolean } };
```

with the multi-line form:

```typescript
seccompDetails?: {
  execve?: boolean;
  fileMonitor?: { enabled?: boolean; enforceWithoutFuse?: boolean; interceptMetadata?: boolean; openatEmulation?: boolean; blockIoUring?: boolean };
  blockedSocketFamilies?: Array<{
    family: string;
    action?: 'errno' | 'kill' | 'log' | 'log_and_kill';
  }>;
};
```

- [ ] **Step 2: Verify typecheck passes**

Run: `npm run typecheck`
Expected: PASS (no errors). The type is additive.

- [ ] **Step 3: Commit**

```bash
git add src/core/config.ts
git commit -m "feat(config): add blockedSocketFamilies type to seccompDetails"
```

---

## Task 2: Emit `blocked_socket_families: []` when caller passes opt-out

**Files:**
- Modify: `src/core/config.ts:317` (inside the `if (opts.seccompDetails)` block, after the `fileMonitor` block)
- Test: `src/core/config.test.ts` (new test added after the existing `'generates seccomp details with file_monitor'` test on line 282)

- [ ] **Step 1: Write the failing test**

Add this test to `src/core/config.test.ts` immediately after the existing `'generates seccomp details with file_monitor'` test (after the closing `});` of that test, before `'generates cgroups section'`):

```typescript
  it('emits blocked_socket_families: [] for explicit opt-out', () => {
    const result = generateServerConfig({
      seccompDetails: { blockedSocketFamilies: [] },
    });
    const parsed = yaml.load(result) as any;
    expect(parsed.sandbox.seccomp.enabled).toBe(true);
    expect(parsed.sandbox.seccomp.blocked_socket_families).toEqual([]);
    expect(Array.isArray(parsed.sandbox.seccomp.blocked_socket_families)).toBe(true);
  });
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run src/core/config.test.ts -t "blocked_socket_families: \\[\\]"`
Expected: FAIL — `blocked_socket_families` is undefined (we haven't emitted it yet).

- [ ] **Step 3: Implement the emission**

In `src/core/config.ts`, inside the `if (opts.seccompDetails) { ... }` block (around lines 298–317), after the `fileMonitor` block ends (after the closing `}` on line 316), add:

```typescript
    if (opts.seccompDetails.blockedSocketFamilies !== undefined) {
      sec.blocked_socket_families = opts.seccompDetails.blockedSocketFamilies.map(e => ({
        family: e.family,
        ...(e.action !== undefined && { action: e.action }),
      }));
    }
```

The `!== undefined` check is critical — `[]` is truthy-falsy edge: a plain `if (...)` would treat `[]` as truthy (so this case is fine), but using `!== undefined` makes intent explicit and parallels how agentsh distinguishes nil from non-nil-empty.

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run src/core/config.test.ts -t "blocked_socket_families: \\[\\]"`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/core/config.ts src/core/config.test.ts
git commit -m "feat(config): emit blocked_socket_families opt-out

Setting seccompDetails.blockedSocketFamilies to [] emits an explicit
empty array, which agentsh v0.19.0 treats as opt-out from its default
12-family block list."
```

---

## Task 3: Emit populated `blocked_socket_families` list

**Files:**
- Test: `src/core/config.test.ts` (new test after Task 2's test)

The implementation is already in place from Task 2 — this task verifies populated lists serialize correctly, including the optional `action` field.

- [ ] **Step 1: Write the failing test**

Add this test in `src/core/config.test.ts` immediately after the test from Task 2:

```typescript
  it('emits populated blocked_socket_families with optional action per entry', () => {
    const result = generateServerConfig({
      seccompDetails: {
        blockedSocketFamilies: [
          { family: 'AF_VSOCK', action: 'log_and_kill' },
          { family: 'AF_ALG' },
          { family: '38', action: 'errno' },
        ],
      },
    });
    const parsed = yaml.load(result) as any;
    expect(parsed.sandbox.seccomp.blocked_socket_families).toEqual([
      { family: 'AF_VSOCK', action: 'log_and_kill' },
      { family: 'AF_ALG' },
      { family: '38', action: 'errno' },
    ]);
  });
```

- [ ] **Step 2: Run test to verify it passes**

Run: `npx vitest run src/core/config.test.ts -t "populated blocked_socket_families"`
Expected: PASS — the Task 2 implementation already handles this.

If it FAILS, the issue is in the Task 2 emission code: confirm that `action` is correctly omitted from entries where the caller didn't supply it. The conditional spread `...(e.action !== undefined && { action: e.action })` should yield `{}` when undefined.

- [ ] **Step 3: Commit**

```bash
git add src/core/config.test.ts
git commit -m "test(config): cover populated blocked_socket_families list"
```

---

## Task 4: Verify omitted case leaves field absent (defaults pathway)

**Files:**
- Test: `src/core/config.test.ts`

This task locks in the "field omitted → agentsh applies defaults" contract.

- [ ] **Step 1: Write the test**

Add to `src/core/config.test.ts` after the Task 3 test:

```typescript
  it('omits blocked_socket_families when field is unset (lets agentsh apply defaults)', () => {
    const result = generateServerConfig({
      seccompDetails: { execve: true },
    });
    const parsed = yaml.load(result) as any;
    expect(parsed.sandbox.seccomp.blocked_socket_families).toBeUndefined();
  });
```

- [ ] **Step 2: Run test to verify it passes**

Run: `npx vitest run src/core/config.test.ts -t "omits blocked_socket_families"`
Expected: PASS — the `!== undefined` guard prevents emission.

- [ ] **Step 3: Commit**

```bash
git add src/core/config.test.ts
git commit -m "test(config): assert blocked_socket_families absent when unset"
```

---

## Task 5: Cover implicit enablement and ptrace precedence

**Files:**
- Test: `src/core/config.test.ts`

These tests confirm `blockedSocketFamilies` participates in existing `seccompDetails` rules: passing it alone implicitly enables seccomp; ptrace still wins precedence.

- [ ] **Step 1: Write the tests**

Add to `src/core/config.test.ts` after the Task 4 test:

```typescript
  it('blockedSocketFamilies alone implicitly enables seccomp', () => {
    const result = generateServerConfig({
      seccompDetails: {
        blockedSocketFamilies: [{ family: 'AF_VSOCK' }],
      },
    });
    const parsed = yaml.load(result) as any;
    expect(parsed.sandbox.seccomp.enabled).toBe(true);
    expect(parsed.sandbox.seccomp.blocked_socket_families).toEqual([{ family: 'AF_VSOCK' }]);
  });

  it('ptrace precedence: seccomp stays disabled even with blockedSocketFamilies set', () => {
    const result = generateServerConfig({
      ptrace: { enabled: true },
      seccompDetails: {
        blockedSocketFamilies: [{ family: 'AF_VSOCK', action: 'log' }],
      },
    });
    const parsed = yaml.load(result) as any;
    expect(parsed.sandbox.seccomp.enabled).toBe(false);
    // Field still emitted so agentsh's ptrace fallback engine can pick it up.
    expect(parsed.sandbox.seccomp.blocked_socket_families).toEqual([
      { family: 'AF_VSOCK', action: 'log' },
    ]);
  });
```

- [ ] **Step 2: Run tests to verify they pass**

Run: `npx vitest run src/core/config.test.ts -t "implicitly enables seccomp"`
Run: `npx vitest run src/core/config.test.ts -t "ptrace precedence"`
Expected: both PASS — the existing line `if (!opts.ptrace?.enabled) sec.enabled = true;` handles both cases. The field is always emitted regardless of which engine ends up servicing it (agentsh wires the ptrace engine via the same config field).

- [ ] **Step 3: Commit**

```bash
git add src/core/config.test.ts
git commit -m "test(config): cover seccomp enablement + ptrace precedence with blockedSocketFamilies"
```

---

## Task 6: Bump pinned agentsh version to 0.19.0

**Files:**
- Modify: `src/core/integrity.ts:3,6` (PINNED_VERSION + new CHECKSUMS entry)
- Modify: `src/adapters/freestyle.ts:8`
- Modify: `scripts/build-sandbox-images.ts:22`
- Modify: `src/adapters/adapters.test.ts:1234`

All four edits land together — the install-script test asserts the literal that comes from `freestyle.ts`.

- [ ] **Step 1: Update `src/core/integrity.ts`**

Change line 3:

```typescript
export const PINNED_VERSION = '0.19.0';
```

Add a new entry to `CHECKSUMS` (insert before the existing `'0.18.3': { ... }` block, so 0.19.0 is the first listed):

```typescript
  '0.19.0': {
    linux_amd64:
      '04c1b0e958a6e9027fc85d4625bec765e459f191dc16c4c5a04468c867f71d85',
    linux_arm64:
      '89cecae90e6511cf96019cca948e3b5142dce329349141eb838979a243dda9cd',
  },
```

(Checksums sourced from the upstream v0.19.0 release `checksums.txt`.)

- [ ] **Step 2: Update `src/adapters/freestyle.ts:8`**

Change:

```typescript
const AGENTSH_VERSION = '0.19.0';
```

- [ ] **Step 3: Update `scripts/build-sandbox-images.ts:22`**

Change:

```typescript
const AGENTSH_VERSION = '0.19.0';
```

- [ ] **Step 4: Update `src/adapters/adapters.test.ts:1234`**

Change:

```typescript
expect(files['/opt/install-agentsh.sh'].content).toContain('AGENTSH_VERSION="0.19.0"');
```

- [ ] **Step 5: Run typecheck and tests**

Run: `npm run typecheck`
Expected: PASS.

Run: `npm test`
Expected: PASS — all tests including the bumped adapter assertion. If anything fails, fix in place; do not commit until green.

- [ ] **Step 6: Commit**

```bash
git add src/core/integrity.ts src/adapters/freestyle.ts scripts/build-sandbox-images.ts src/adapters/adapters.test.ts
git commit -m "chore: bump pinned agentsh to v0.19.0

Adds linux_amd64 + linux_arm64 SHA-256 checksums for the v0.19.0 release.
Older entries retained for callers that pin via agentshVersion.

Brings in v0.19.0 features:
- Per-AF_* socket family blocking on socket(2)/socketpair(2)
  (sandbox.seccomp.blocked_socket_families) — exposed via
  serverConfig.seccompDetails.blockedSocketFamilies."
```

---

## Task 7: README note + final verification

**Files:**
- Modify: `README.md` (appropriate location — find an existing seccomp/security-features section, or add near the configuration examples)

- [ ] **Step 1: Locate the right README spot**

Run: `grep -n "seccomp\|secure-sandbox\|## " README.md | head -30`

Pick an existing section that documents server-config knobs or security defaults. If no fitting section exists, add a new short subsection under the existing Configuration / Security area.

- [ ] **Step 2: Add the note**

Add a short paragraph (3–5 lines), e.g.:

```markdown
### Socket family blocking

By default, secure-sandbox blocks 12 niche `AF_*` socket families (AF_ALG, AF_VSOCK, AF_RDS, AF_TIPC, AF_KCM, AF_X25, AF_AX25, AF_NETROM, AF_ROSE, AF_DECnet, AF_APPLETALK, AF_IPX) at `EAFNOSUPPORT` to mitigate the recurring CVE class where `socket(AF_<niche>, ...)` is the kernel attack entry point. Override the list via `serverConfig.seccompDetails.blockedSocketFamilies` or opt out entirely with `[]`. See [agentsh's seccomp docs](https://github.com/canyonroad/agentsh/blob/main/docs/seccomp.md#socket-family-blocking) for the full default list and audit event shape.
```

Do not duplicate the canonical agentsh docs — keep the README brief and link out.

- [ ] **Step 3: Run the full test suite + build one more time**

Run: `npm run typecheck && npm test && npm run build`
Expected: all PASS, build artifacts produced under `dist/`.

- [ ] **Step 4: Commit**

```bash
git add README.md
git commit -m "docs(readme): note default socket family blocking + override knob"
```

---

## Verification

End-to-end check that the change hangs together:

1. `npm run typecheck` — confirms the new field types compile and don't break consumers.
2. `npm test` — runs vitest; expect 5 new tests (Tasks 2–5) plus the bumped adapter literal (Task 6) all green.
3. `npm run build` — confirms `tsup` emits the new field in `dist/core/config.d.ts` (spot-check that `blockedSocketFamilies` appears in the declaration file).
4. Sanity grep: `grep -rn "0.18.3" src/ scripts/ 2>/dev/null` — should return zero hits in non-comment, non-`integrity.ts`-history lines (the entry in CHECKSUMS for 0.18.3 is intentionally retained).
5. Manual integration (optional, requires a Linux host with seccomp): build with `AGENTSH_VERSION=0.19.0`, configure `seccompDetails: { blockedSocketFamilies: [{ family: 'AF_VSOCK', action: 'log' }] }`, run a small program that calls `socket(AF_VSOCK, SOCK_STREAM, 0)`, confirm it returns `EAFNOSUPPORT` and a `seccomp_socket_family_blocked` audit event lands.

## Critical files (recap)

- `src/core/config.ts` — type extension (Task 1) + emission (Task 2)
- `src/core/config.test.ts` — 5 new tests (Tasks 2–5)
- `src/core/integrity.ts` — version pin + checksums (Task 6)
- `src/adapters/freestyle.ts` — install script version (Task 6)
- `scripts/build-sandbox-images.ts` — image build version (Task 6)
- `src/adapters/adapters.test.ts:1234` — version literal (Task 6)
- `README.md` — short note (Task 7)
