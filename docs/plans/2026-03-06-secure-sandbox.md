# @agentsh/secure-sandbox Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement the @agentsh/secure-sandbox TypeScript library per SPEC-v2.md — policy system, provisioning flow, runtime wrapper, and three adapters (Vercel, E2B, Daytona).

**Architecture:** Adapter pattern normalizes sandbox providers behind `SandboxAdapter`. Provisioning installs agentsh + writes policy via raw adapter. Runtime routes all ops through `agentsh exec` via adapter-as-transport. Policy defined as TypeScript objects, validated with Zod, serialized to YAML.

**Tech Stack:** TypeScript (ESM), Zod, js-yaml, vitest, tsup

**Reference:** `docs/SPEC-v2.md` — the authoritative spec. Read relevant sections before each task.

---

### Task 1: Project Scaffold

**Files:**
- Create: `package.json`
- Create: `tsconfig.json`
- Create: `tsup.config.ts`
- Create: `vitest.config.ts`
- Create: `.gitignore`
- Create: `src/` directory structure

**Step 1: Initialize git repo**

```bash
cd /home/eran/work/canyonroad/secure-sandbox
git init
```

**Step 2: Create package.json**

```json
{
  "name": "@agentsh/secure-sandbox",
  "version": "0.1.0",
  "type": "module",
  "exports": {
    ".": {
      "types": "./dist/index.d.ts",
      "import": "./dist/index.js"
    },
    "./adapters": {
      "types": "./dist/adapters/index.d.ts",
      "import": "./dist/adapters/index.js"
    },
    "./adapters/vercel": {
      "types": "./dist/adapters/vercel.d.ts",
      "import": "./dist/adapters/vercel.js"
    },
    "./adapters/e2b": {
      "types": "./dist/adapters/e2b.d.ts",
      "import": "./dist/adapters/e2b.js"
    },
    "./adapters/daytona": {
      "types": "./dist/adapters/daytona.d.ts",
      "import": "./dist/adapters/daytona.js"
    },
    "./policies": {
      "types": "./dist/policies/index.d.ts",
      "import": "./dist/policies/index.js"
    },
    "./testing": {
      "types": "./dist/testing/index.d.ts",
      "import": "./dist/testing/index.js"
    }
  },
  "files": ["dist"],
  "scripts": {
    "build": "tsup",
    "test": "vitest run",
    "test:watch": "vitest",
    "typecheck": "tsc --noEmit",
    "prepublishOnly": "npm run build"
  },
  "dependencies": {
    "js-yaml": "^4.1.0",
    "zod": "^3.24.0"
  },
  "devDependencies": {
    "@types/js-yaml": "^4.0.9",
    "tsup": "^8.4.0",
    "typescript": "^5.7.0",
    "vitest": "^3.0.0"
  },
  "peerDependencies": {
    "@vercel/sandbox": "^1.0.0",
    "@e2b/code-interpreter": "^1.2.0",
    "@daytonaio/sdk": "^0.12.0 || ^1.0.0"
  },
  "peerDependenciesMeta": {
    "@vercel/sandbox": { "optional": true },
    "@e2b/code-interpreter": { "optional": true },
    "@daytonaio/sdk": { "optional": true }
  }
}
```

**Step 3: Create tsconfig.json**

```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "ESNext",
    "moduleResolution": "bundler",
    "declaration": true,
    "declarationMap": true,
    "sourceMap": true,
    "outDir": "dist",
    "rootDir": "src",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true,
    "resolveJsonModule": true,
    "isolatedModules": true
  },
  "include": ["src"],
  "exclude": ["node_modules", "dist", "**/*.test.ts"]
}
```

**Step 4: Create tsup.config.ts**

```ts
import { defineConfig } from 'tsup';

export default defineConfig({
  entry: [
    'src/index.ts',
    'src/adapters/index.ts',
    'src/adapters/vercel.ts',
    'src/adapters/e2b.ts',
    'src/adapters/daytona.ts',
    'src/policies/index.ts',
    'src/testing/index.ts',
  ],
  format: ['esm'],
  dts: true,
  sourcemap: true,
  clean: true,
  outDir: 'dist',
});
```

**Step 5: Create vitest.config.ts**

```ts
import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    include: ['src/**/*.test.ts'],
  },
});
```

**Step 6: Create .gitignore**

```
node_modules/
dist/
*.tgz
.DS_Store
```

**Step 7: Create directory structure with placeholder files**

```bash
mkdir -p src/{core,adapters,policies,testing}
touch src/index.ts
touch src/core/{types,provision,runtime,integrity,snapshot}.ts
touch src/adapters/{index,vercel,e2b,daytona}.ts
touch src/policies/{index,schema,presets,serialize}.ts
touch src/testing/index.ts
```

**Step 8: Install dependencies and verify**

```bash
npm install
npx tsc --noEmit
```

**Step 9: Commit**

```bash
git add -A
git commit -m "chore: project scaffold with package.json, tsconfig, tsup, vitest"
```

---

### Task 2: Core Types & Error Classes

**Ref:** SPEC-v2.md Sections 6, 8, 12

**Files:**
- Create: `src/core/types.ts`
- Create: `src/core/errors.ts`
- Create: `src/core/errors.test.ts`

**Step 1: Write types.ts**

All interfaces from SPEC-v2.md Sections 6 and 8. These are type-only — no runtime code, no tests needed. Include:

- `ExecResult` — `{ stdout, stderr, exitCode }`
- `SandboxAdapter` — 3 required methods (`exec`, `writeFile`, `readFile`), 2 optional (`stop`, `fileExists`)
- `SecuredSandbox` — `exec`, `writeFile`, `readFile`, `stop`, `sessionId`, `securityMode`
- `WriteFileResult` — discriminated union: `{ success: true; path } | { success: false; path; error }`
- `ReadFileResult` — discriminated union: `{ success: true; path; content } | { success: false; path; error }`
- `SecurityMode` — `'full' | 'landlock' | 'landlock-only' | 'minimal'`
- `InstallStrategy` — `'preinstalled' | 'download' | 'upload'`
- `SecureConfig` — all 12 fields from SPEC-v2.md Section 5.1
- `CreateSandboxConfig` — extends SecureConfig with Vercel-specific fields

Key detail for `SandboxAdapter.exec`:
```ts
exec(
  cmd: string,
  args?: string[],
  opts?: {
    cwd?: string;
    sudo?: boolean;
    detached?: boolean;
  },
): Promise<ExecResult>;
```

Key detail for `SecuredSandbox.exec`:
```ts
exec(
  command: string,
  opts?: { cwd?: string; timeout?: number },
): Promise<ExecResult>;
```

**Step 2: Write errors.ts**

Seven error classes per SPEC-v2.md Section 12:

```ts
export class AgentSHError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'AgentSHError';
  }
}

export class PolicyValidationError extends AgentSHError { issues: ZodIssue[]; ... }
export class MissingPeerDependencyError extends AgentSHError { packageName: string; versionRange: string; ... }
export class IncompatibleProviderVersionError extends AgentSHError { installed: string; required: string; ... }
export class ProvisioningError extends AgentSHError { phase: string; command: string; stderr: string; ... }
export class IntegrityError extends AgentSHError { expected: string; actual: string; ... }
export class RuntimeError extends AgentSHError { sessionId: string; command: string; stderr: string; ... }
```

Each constructor takes an object with the class-specific fields and generates a descriptive message. See SPEC-v2.md Section 12.2 for the `IncompatibleProviderVersionError` message format example.

**Step 3: Write failing tests for errors**

`src/core/errors.test.ts` — test each error class:
- Extends `AgentSHError`
- `instanceof` checks work for both the specific class and `AgentSHError`
- Properties are set correctly
- Message is generated from properties
- Test `IncompatibleProviderVersionError` message format matches:
  `"@daytonaio/sdk version 0.10.3 is not supported. @agentsh/secure-sandbox requires @daytonaio/sdk ^0.12.0 || ^1.0.0."`

**Step 4: Run tests to verify they fail**

```bash
npx vitest run src/core/errors.test.ts
```
Expected: FAIL (imports not resolving yet)

**Step 5: Implement error classes, run tests to verify they pass**

```bash
npx vitest run src/core/errors.test.ts
```
Expected: all PASS

**Step 6: Typecheck**

```bash
npx tsc --noEmit
```

**Step 7: Commit**

```bash
git add src/core/types.ts src/core/errors.ts src/core/errors.test.ts
git commit -m "feat: core types and error classes"
```

---

### Task 3: Policy Schema (Zod)

**Ref:** SPEC-v2.md Sections 9.1, 9.2, 9.7

**Files:**
- Create: `src/policies/schema.ts`
- Create: `src/policies/schema.test.ts`

**Step 1: Write failing tests**

`src/policies/schema.test.ts`:

```ts
import { describe, it, expect } from 'vitest';
import { PolicyDefinitionSchema } from './schema.js';

describe('PolicyDefinitionSchema', () => {
  it('accepts valid file allow rule', () => {
    const result = PolicyDefinitionSchema.safeParse({
      file: [{ allow: '/workspace/**', ops: ['read', 'write'] }],
    });
    expect(result.success).toBe(true);
  });

  it('accepts file deny rule with string array', () => {
    const result = PolicyDefinitionSchema.safeParse({
      file: [{ deny: ['**/.env', '~/.ssh/**'] }],
    });
    expect(result.success).toBe(true);
  });

  it('accepts file deny rule with single string', () => {
    const result = PolicyDefinitionSchema.safeParse({
      file: [{ deny: '**/.env' }],
    });
    expect(result.success).toBe(true);
  });

  it('accepts file redirect rule', () => {
    const result = PolicyDefinitionSchema.safeParse({
      file: [{ redirect: '/secret', to: '/dev/null', ops: ['read'] }],
    });
    expect(result.success).toBe(true);
  });

  it('accepts network allow with ports', () => {
    const result = PolicyDefinitionSchema.safeParse({
      network: [{ allow: ['registry.npmjs.org'], ports: [443] }],
    });
    expect(result.success).toBe(true);
  });

  it('accepts network deny wildcard', () => {
    const result = PolicyDefinitionSchema.safeParse({
      network: [{ deny: '*' }],
    });
    expect(result.success).toBe(true);
  });

  it('accepts command deny list', () => {
    const result = PolicyDefinitionSchema.safeParse({
      commands: [{ deny: ['env', 'printenv'] }],
    });
    expect(result.success).toBe(true);
  });

  it('accepts command redirect with object target', () => {
    const result = PolicyDefinitionSchema.safeParse({
      commands: [{ redirect: ['curl', 'wget'], to: { cmd: 'agentsh-fetch', args: ['--audit'] } }],
    });
    expect(result.success).toBe(true);
  });

  it('accepts env rules', () => {
    const result = PolicyDefinitionSchema.safeParse({
      env: [{ commands: ['node'], allow: ['PATH', 'HOME'] }],
    });
    expect(result.success).toBe(true);
  });

  it('accepts dns redirects', () => {
    const result = PolicyDefinitionSchema.safeParse({
      dns: [{ match: '.*\\.example\\.com', resolveTo: '127.0.0.1' }],
    });
    expect(result.success).toBe(true);
  });

  it('accepts connect redirects', () => {
    const result = PolicyDefinitionSchema.safeParse({
      connect: [{ match: 'api.prod.com:443', redirectTo: 'localhost:8080' }],
    });
    expect(result.success).toBe(true);
  });

  it('accepts empty policy', () => {
    const result = PolicyDefinitionSchema.safeParse({});
    expect(result.success).toBe(true);
  });

  it('accepts full agentDefault-style policy', () => {
    const result = PolicyDefinitionSchema.safeParse({
      file: [
        { allow: '/workspace/**', ops: ['read', 'write', 'create'] },
        { deny: ['/workspace/.git/config', '/workspace/.netrc'] },
        { deny: ['**/.env', '**/.env.*', '**/credentials*', '~/.ssh/**'] },
        { deny: '/proc/*/environ' },
      ],
      network: [
        { allow: ['registry.npmjs.org', 'registry.yarnpkg.com', 'pypi.org', 'files.pythonhosted.org'], ports: [443] },
        { deny: '*' },
      ],
      commands: [
        { deny: ['env', 'printenv', 'sudo', 'su', 'doas'] },
        { deny: ['shutdown', 'reboot', 'halt', 'poweroff'] },
        { deny: ['nc', 'ncat', 'netcat', 'socat', 'telnet'] },
        { deny: ['git push --force', 'git reset --hard'] },
        { redirect: ['curl', 'wget'], to: { cmd: 'agentsh-fetch', args: ['--audit'] } },
      ],
    });
    expect(result.success).toBe(true);
  });

  it('rejects invalid file op', () => {
    const result = PolicyDefinitionSchema.safeParse({
      file: [{ allow: '/workspace/**', ops: ['execute'] }],
    });
    expect(result.success).toBe(false);
  });

  it('rejects file rule with no decision key', () => {
    const result = PolicyDefinitionSchema.safeParse({
      file: [{ paths: '/workspace/**' }],
    });
    expect(result.success).toBe(false);
  });

  it('rejects unknown top-level key', () => {
    const result = PolicyDefinitionSchema.safeParse({
      file: [{ allow: '/workspace/**' }],
      unknown: 'field',
    });
    expect(result.success).toBe(false);
  });
});
```

**Step 2: Run tests to verify they fail**

```bash
npx vitest run src/policies/schema.test.ts
```

**Step 3: Implement schema.ts**

Build Zod schemas for each rule type per SPEC-v2.md Section 9.2. Key design:

- `stringOrArray` = `z.union([z.string(), z.array(z.string())])`
- `FileOpSchema` = `z.enum(['read', 'write', 'create', 'delete'])`
- `FileRuleSchema` = `z.discriminatedUnion(...)` — but Zod doesn't support discriminated unions on different key presence. Use `z.union()` with 5 variants (allow, deny, redirect, audit, softDelete). Each variant uses `z.object({ allow: stringOrArray, ops: ... }).strict()` etc.
- `NetworkRuleSchema`, `CommandRuleSchema`, `EnvRuleSchema`, `DnsRedirectSchema`, `ConnectRedirectSchema` — same pattern.
- `PolicyDefinitionSchema` = `z.object({ file, network, commands, env, dns, connect }).strict()` with all optional.

Export `PolicyDefinitionSchema` and the inferred `PolicyDefinition` type.

Also export a `validatePolicy(policy: unknown): PolicyDefinition` function that calls `PolicyDefinitionSchema.parse()` and wraps ZodError in `PolicyValidationError`.

**Step 4: Run tests**

```bash
npx vitest run src/policies/schema.test.ts
```
Expected: all PASS

**Step 5: Commit**

```bash
git add src/policies/schema.ts src/policies/schema.test.ts
git commit -m "feat: Zod schema for PolicyDefinition with validation"
```

---

### Task 4: Policy Presets

**Ref:** SPEC-v2.md Section 9.5

**Files:**
- Create: `src/policies/presets.ts`
- Create: `src/policies/presets.test.ts`

**Step 1: Write failing tests**

Test each of the 4 presets:

```ts
import { describe, it, expect } from 'vitest';
import { agentDefault, devSafe, ciStrict, agentSandbox } from './presets.js';
import { PolicyDefinitionSchema } from './schema.js';

describe('presets', () => {
  describe('agentDefault', () => {
    it('returns a valid PolicyDefinition', () => {
      const policy = agentDefault();
      expect(PolicyDefinitionSchema.safeParse(policy).success).toBe(true);
    });

    it('denies env and printenv', () => {
      const policy = agentDefault();
      const denyCommands = policy.commands!
        .filter((r): r is { deny: string | string[] } => 'deny' in r)
        .flatMap(r => Array.isArray(r.deny) ? r.deny : [r.deny]);
      expect(denyCommands).toContain('env');
      expect(denyCommands).toContain('printenv');
    });

    it('denies network by default', () => {
      const policy = agentDefault();
      const lastNetRule = policy.network![policy.network!.length - 1];
      expect('deny' in lastNetRule && lastNetRule.deny).toBe('*');
    });

    it('allows workspace read/write/create', () => {
      const policy = agentDefault();
      const firstFileRule = policy.file![0];
      expect('allow' in firstFileRule && firstFileRule.allow).toBe('/workspace/**');
    });

    it('accepts extensions and appends them', () => {
      const policy = agentDefault({
        network: [{ allow: ['api.stripe.com'], ports: [443] }],
      });
      expect(PolicyDefinitionSchema.safeParse(policy).success).toBe(true);
      // Extension appended after base rules
      const networkRules = policy.network!;
      const lastRule = networkRules[networkRules.length - 1];
      expect('allow' in lastRule && lastRule.allow).toContain('api.stripe.com');
    });
  });

  describe('devSafe', () => {
    it('returns a valid PolicyDefinition', () => {
      expect(PolicyDefinitionSchema.safeParse(devSafe()).success).toBe(true);
    });

    it('does not deny all network (more permissive)', () => {
      const policy = devSafe();
      const hasDenyAll = policy.network!.some(r => 'deny' in r && r.deny === '*');
      expect(hasDenyAll).toBe(false);
    });
  });

  describe('ciStrict', () => {
    it('returns a valid PolicyDefinition', () => {
      expect(PolicyDefinitionSchema.safeParse(ciStrict()).success).toBe(true);
    });

    it('denies all files outside workspace', () => {
      const policy = ciStrict();
      const denyAll = policy.file!.find(r => 'deny' in r && r.deny === '/**');
      expect(denyAll).toBeDefined();
    });
  });

  describe('agentSandbox', () => {
    it('returns a valid PolicyDefinition', () => {
      expect(PolicyDefinitionSchema.safeParse(agentSandbox()).success).toBe(true);
    });

    it('only allows read on workspace', () => {
      const policy = agentSandbox();
      const allowRule = policy.file![0] as { allow: string; ops?: string[] };
      expect(allowRule.ops).toEqual(['read']);
    });
  });
});
```

**Step 2: Run tests to verify failure**

```bash
npx vitest run src/policies/presets.test.ts
```

**Step 3: Implement presets.ts**

Each preset is a function returning `PolicyDefinition`. Match the exact rule sets from SPEC-v2.md Section 9.5. Extensions are appended per-category using array concat:

```ts
import type { PolicyDefinition } from './schema.js';
import { validatePolicy } from './schema.js';

export function agentDefault(extensions?: Partial<PolicyDefinition>): PolicyDefinition {
  const base: PolicyDefinition = {
    file: [
      { allow: '/workspace/**', ops: ['read', 'write', 'create'] },
      { deny: ['/workspace/.git/config', '/workspace/.netrc'] },
      { deny: ['**/.env', '**/.env.*', '**/credentials*', '~/.ssh/**'] },
      { deny: '/proc/*/environ' },
    ],
    network: [ /* ... from spec ... */ ],
    commands: [ /* ... from spec ... */ ],
  };
  if (!extensions) return validatePolicy(base);
  return validatePolicy(mergeAppend(base, extensions));
}
// ... devSafe, ciStrict, agentSandbox similarly
```

The internal `mergeAppend` used here is a simple per-key array concat. It gets extracted into the public `merge()` in the next task.

**Step 4: Run tests**

```bash
npx vitest run src/policies/presets.test.ts
```

**Step 5: Commit**

```bash
git add src/policies/presets.ts src/policies/presets.test.ts
git commit -m "feat: policy presets — agentDefault, devSafe, ciStrict, agentSandbox"
```

---

### Task 5: Policy Merge Utilities

**Ref:** SPEC-v2.md Section 9.6

**Files:**
- Create: `src/policies/merge.ts`
- Create: `src/policies/merge.test.ts`
- Modify: `src/policies/presets.ts` (use shared merge logic)

**Step 1: Write failing tests**

```ts
import { describe, it, expect } from 'vitest';
import { merge, mergePrepend } from './merge.js';

describe('merge', () => {
  it('appends extension rules after base', () => {
    const result = merge(
      { file: [{ allow: '/workspace/**' }] },
      { file: [{ deny: '**/.env' }] },
    );
    expect(result.file).toHaveLength(2);
    expect(result.file![0]).toEqual({ allow: '/workspace/**' });
    expect(result.file![1]).toEqual({ deny: '**/.env' });
  });

  it('preserves categories not in extensions', () => {
    const result = merge(
      { file: [{ allow: '/workspace/**' }], network: [{ deny: '*' }] },
      { file: [{ deny: '**/.env' }] },
    );
    expect(result.network).toEqual([{ deny: '*' }]);
  });

  it('handles multiple overrides', () => {
    const result = merge(
      { commands: [{ deny: ['env'] }] },
      { commands: [{ deny: ['sudo'] }] },
      { commands: [{ allow: ['ls'] }] },
    );
    expect(result.commands).toHaveLength(3);
  });

  it('validates the merged result', () => {
    expect(() => merge(
      { file: [{ allow: '/workspace/**' }] },
      { file: [{ invalid: true } as any] },
    )).toThrow();
  });
});

describe('mergePrepend', () => {
  it('prepends extension rules before base', () => {
    const result = mergePrepend(
      { file: [{ deny: '/**' }] },
      { file: [{ allow: '/etc/resolv.conf', ops: ['read'] }] },
    );
    expect(result.file).toHaveLength(2);
    expect(result.file![0]).toEqual({ allow: '/etc/resolv.conf', ops: ['read'] });
    expect(result.file![1]).toEqual({ deny: '/**' });
  });
});
```

**Step 2: Run tests to verify failure**

```bash
npx vitest run src/policies/merge.test.ts
```

**Step 3: Implement merge.ts**

```ts
import type { PolicyDefinition } from './schema.js';
import { validatePolicy } from './schema.js';

const CATEGORIES = ['file', 'network', 'commands', 'env', 'dns', 'connect'] as const;

export function merge(base: PolicyDefinition, ...overrides: Partial<PolicyDefinition>[]): PolicyDefinition {
  return validatePolicy(mergeInternal(base, overrides, 'append'));
}

export function mergePrepend(base: PolicyDefinition, ...overrides: Partial<PolicyDefinition>[]): PolicyDefinition {
  return validatePolicy(mergeInternal(base, overrides, 'prepend'));
}

function mergeInternal(
  base: PolicyDefinition,
  overrides: Partial<PolicyDefinition>[],
  mode: 'append' | 'prepend',
): PolicyDefinition {
  const result = { ...base };
  for (const override of overrides) {
    for (const key of CATEGORIES) {
      if (override[key]) {
        const baseRules = result[key] ?? [];
        result[key] = mode === 'append'
          ? [...baseRules, ...override[key]!]
          : [...override[key]!, ...baseRules];
      }
    }
  }
  return result;
}
```

**Step 4: Refactor presets.ts to use merge internally**

Replace the internal `mergeAppend` in presets with the shared `merge` from `./merge.js`.

**Step 5: Run all policy tests**

```bash
npx vitest run src/policies/
```

**Step 6: Commit**

```bash
git add src/policies/merge.ts src/policies/merge.test.ts src/policies/presets.ts
git commit -m "feat: merge() and mergePrepend() for policy composition"
```

---

### Task 6: Policy Serialization

**Ref:** SPEC-v2.md Sections 9.3, 9.4

**Files:**
- Create: `src/policies/serialize.ts`
- Create: `src/policies/serialize.test.ts`

**Step 1: Write failing tests**

Test two functions: `serializePolicy(policy) → string` (user policy YAML) and `systemPolicyYaml() → string` (fixed system policy).

```ts
import { describe, it, expect } from 'vitest';
import yaml from 'js-yaml';
import { serializePolicy, systemPolicyYaml } from './serialize.js';

describe('serializePolicy', () => {
  it('serializes file deny rule', () => {
    const result = serializePolicy({
      file: [{ deny: ['**/.env', '~/.ssh/**'] }],
    });
    const parsed = yaml.load(result) as any;
    expect(parsed.file_rules).toHaveLength(1);
    expect(parsed.file_rules[0].name).toBe('file-rule-0');
    expect(parsed.file_rules[0].paths).toEqual(['**/.env', '~/.ssh/**']);
    expect(parsed.file_rules[0].decision).toBe('deny');
  });

  it('serializes file allow rule with ops', () => {
    const result = serializePolicy({
      file: [{ allow: '/workspace/**', ops: ['read', 'write'] }],
    });
    const parsed = yaml.load(result) as any;
    expect(parsed.file_rules[0].decision).toBe('allow');
    expect(parsed.file_rules[0].operations).toEqual(['read', 'write']);
    expect(parsed.file_rules[0].paths).toEqual(['/workspace/**']);
  });

  it('normalizes single string to array', () => {
    const result = serializePolicy({
      file: [{ deny: '**/.env' }],
    });
    const parsed = yaml.load(result) as any;
    expect(parsed.file_rules[0].paths).toEqual(['**/.env']);
  });

  it('serializes command redirect with object target', () => {
    const result = serializePolicy({
      commands: [{ redirect: ['curl', 'wget'], to: { cmd: 'agentsh-fetch', args: ['--audit'] } }],
    });
    const parsed = yaml.load(result) as any;
    expect(parsed.command_rules[0].decision).toBe('redirect');
    expect(parsed.command_rules[0].redirect_to.command).toBe('agentsh-fetch');
    expect(parsed.command_rules[0].redirect_to.args).toEqual(['--audit']);
  });

  it('serializes command redirect with string target', () => {
    const result = serializePolicy({
      commands: [{ redirect: 'curl', to: '/usr/local/bin/safe-curl' }],
    });
    const parsed = yaml.load(result) as any;
    expect(parsed.command_rules[0].redirect_to).toBe('/usr/local/bin/safe-curl');
  });

  it('serializes network rules', () => {
    const result = serializePolicy({
      network: [
        { allow: ['registry.npmjs.org'], ports: [443] },
        { deny: '*' },
      ],
    });
    const parsed = yaml.load(result) as any;
    expect(parsed.network_rules).toHaveLength(2);
    expect(parsed.network_rules[0].decision).toBe('allow');
    expect(parsed.network_rules[0].ports).toEqual([443]);
    expect(parsed.network_rules[1].decision).toBe('deny');
  });

  it('serializes env rules', () => {
    const result = serializePolicy({
      env: [{ commands: ['node'], allow: ['PATH'], deny: ['SECRET'] }],
    });
    const parsed = yaml.load(result) as any;
    expect(parsed.env_rules).toHaveLength(1);
    expect(parsed.env_rules[0].commands).toEqual(['node']);
  });

  it('serializes dns redirects', () => {
    const result = serializePolicy({
      dns: [{ match: '.*\\.example\\.com', resolveTo: '127.0.0.1' }],
    });
    const parsed = yaml.load(result) as any;
    expect(parsed.dns_redirects).toHaveLength(1);
  });

  it('serializes connect redirects', () => {
    const result = serializePolicy({
      connect: [{ match: 'api.prod.com:443', redirectTo: 'localhost:8080' }],
    });
    const parsed = yaml.load(result) as any;
    expect(parsed.connect_redirects).toHaveLength(1);
  });

  it('omits empty categories', () => {
    const result = serializePolicy({ file: [{ allow: '/workspace/**' }] });
    const parsed = yaml.load(result) as any;
    expect(parsed.network_rules).toBeUndefined();
    expect(parsed.command_rules).toBeUndefined();
  });

  it('handles full agentDefault policy', () => {
    // Import agentDefault and serialize — should round-trip
    const { agentDefault } = await import('./presets.js');
    const result = serializePolicy(agentDefault());
    const parsed = yaml.load(result) as any;
    expect(parsed.file_rules.length).toBeGreaterThan(0);
    expect(parsed.network_rules.length).toBeGreaterThan(0);
    expect(parsed.command_rules.length).toBeGreaterThan(0);
  });
});

describe('systemPolicyYaml', () => {
  it('returns valid YAML', () => {
    const result = systemPolicyYaml();
    const parsed = yaml.load(result) as any;
    expect(parsed).toBeDefined();
  });

  it('contains self-protection file rules', () => {
    const parsed = yaml.load(systemPolicyYaml()) as any;
    const names = parsed.file_rules.map((r: any) => r.name);
    expect(names).toContain('_system-protect-config');
    expect(names).toContain('_system-protect-binary');
    expect(names).toContain('_system-protect-shim-files');
  });

  it('contains process protection command rule', () => {
    const parsed = yaml.load(systemPolicyYaml()) as any;
    const names = parsed.command_rules.map((r: any) => r.name);
    expect(names).toContain('_system-protect-process');
  });

  it('all self-protection rules are deny', () => {
    const parsed = yaml.load(systemPolicyYaml()) as any;
    for (const rule of parsed.file_rules) {
      expect(rule.decision).toBe('deny');
    }
    for (const rule of parsed.command_rules) {
      expect(rule.decision).toBe('deny');
    }
  });
});
```

**Step 2: Run tests to verify failure**

```bash
npx vitest run src/policies/serialize.test.ts
```

**Step 3: Implement serialize.ts**

Two exported functions:

`serializePolicy(policy: PolicyDefinition): string` — converts each rule type:
- File rules → `file_rules` array. For each rule, determine the decision key (`allow`/`deny`/`redirect`/`audit`/`softDelete`), extract paths (normalize string to array), add `operations` if `ops` is present, add `redirect_to` for redirect rules. Auto-name as `file-rule-N`.
- Network rules → `network_rules`. Hosts (normalize to array), ports, decision, redirect_to.
- Command rules → `command_rules`. Commands (normalize to array), decision, redirect_to (string or `{ command, args }`).
- Env rules → `env_rules`. Commands, allow, deny arrays.
- DNS → `dns_redirects`. match, resolve_to.
- Connect → `connect_redirects`. match, redirect_to.

Use `js-yaml` `dump()` to produce the final YAML string.

`systemPolicyYaml(): string` — returns the fixed system policy from SPEC-v2.md Section 9.4. This is a static string (or constructed from a fixed object). Include all 4 rules:
- `_system-protect-config` — deny write/create/delete on `/etc/agentsh/**`
- `_system-protect-binary` — deny write/create/delete on `/usr/local/bin/agentsh*`, `/usr/bin/agentsh*`
- `_system-protect-shim-files` — deny write/create/delete on shim and shell binaries
- `_system-protect-process` — deny kill/killall/pkill with args_match agentsh

**Step 4: Run tests**

```bash
npx vitest run src/policies/serialize.test.ts
```

**Step 5: Run all policy tests**

```bash
npx vitest run src/policies/
```

**Step 6: Commit**

```bash
git add src/policies/serialize.ts src/policies/serialize.test.ts
git commit -m "feat: policy serialization to agentsh YAML + system policy"
```

---

### Task 7: Policy Exports & Integration

**Files:**
- Create: `src/policies/index.ts`
- Create: `src/policies/integration.test.ts`

**Step 1: Write policies/index.ts**

Re-export everything the consumer needs:

```ts
export { PolicyDefinitionSchema, validatePolicy } from './schema.js';
export type { PolicyDefinition, FileRule, NetworkRule, CommandRule, EnvRule, DnsRedirect, ConnectRedirect } from './schema.js';
export { agentDefault, devSafe, ciStrict, agentSandbox } from './presets.js';
export { merge, mergePrepend } from './merge.js';
export { serializePolicy, systemPolicyYaml } from './serialize.js';
```

**Step 2: Write integration test**

Test the full flow: preset → extend → serialize → parse YAML → verify structure.

```ts
import { describe, it, expect } from 'vitest';
import yaml from 'js-yaml';
import { agentDefault, merge, mergePrepend, serializePolicy } from './index.js';

describe('policy integration', () => {
  it('preset → extend → serialize round-trip', () => {
    const policy = agentDefault({
      network: [{ allow: ['api.stripe.com'], ports: [443] }],
    });
    const yamlStr = serializePolicy(policy);
    const parsed = yaml.load(yamlStr) as any;

    // Base rules present
    expect(parsed.file_rules.length).toBeGreaterThanOrEqual(4);
    // Extension appended
    const stripeRule = parsed.network_rules.find(
      (r: any) => r.decision === 'allow' && r.hosts?.includes('api.stripe.com'),
    );
    expect(stripeRule).toBeDefined();
  });

  it('mergePrepend puts exception before deny-all', () => {
    const policy = mergePrepend(
      { file: [{ deny: '/**' }] },
      { file: [{ allow: '/etc/resolv.conf', ops: ['read'] }] },
    );
    const yamlStr = serializePolicy(policy);
    const parsed = yaml.load(yamlStr) as any;
    expect(parsed.file_rules[0].decision).toBe('allow');
    expect(parsed.file_rules[1].decision).toBe('deny');
  });
});
```

**Step 3: Run tests**

```bash
npx vitest run src/policies/
```

**Step 4: Commit**

```bash
git add src/policies/index.ts src/policies/integration.test.ts
git commit -m "feat: policy module exports and integration tests"
```

---

### Task 8: Integrity Verification

**Ref:** SPEC-v2.md Sections 4.3, 4.4

**Files:**
- Create: `src/core/integrity.ts`
- Create: `src/core/integrity.test.ts`

**Step 1: Write failing tests**

```ts
import { describe, it, expect, vi } from 'vitest';
import {
  CHECKSUMS,
  getChecksum,
  buildVerifyCommand,
} from './integrity.js';

describe('CHECKSUMS', () => {
  it('has checksums for v0.14.0 linux_amd64', () => {
    expect(CHECKSUMS['0.14.0']['linux_amd64']).toBe(
      '2ab8ba0d6637fe1a5badf840c3db197161a6f9865d721ed216029d229b1b9bbc',
    );
  });

  it('has checksums for v0.14.0 linux_arm64', () => {
    expect(CHECKSUMS['0.14.0']['linux_arm64']).toBe(
      '929d18dd9fe36e9b2fa830d7ae64b4fb481853e743ade8674fcfcdc73470ed53',
    );
  });
});

describe('getChecksum', () => {
  it('returns pinned checksum for known version+arch', () => {
    expect(getChecksum('0.14.0', 'linux_amd64')).toBe(
      '2ab8ba0d6637fe1a5badf840c3db197161a6f9865d721ed216029d229b1b9bbc',
    );
  });

  it('returns override checksum when provided', () => {
    expect(getChecksum('0.14.0', 'linux_amd64', 'custom-hash')).toBe('custom-hash');
  });

  it('throws IntegrityError for unknown version without override', () => {
    expect(() => getChecksum('0.99.0', 'linux_amd64')).toThrow('No pinned checksum');
  });
});

describe('buildVerifyCommand', () => {
  it('returns sha256sum command first', () => {
    const cmds = buildVerifyCommand('/tmp/agentsh.tar.gz');
    expect(cmds[0]).toContain('sha256sum');
  });

  it('includes shasum fallback', () => {
    const cmds = buildVerifyCommand('/tmp/agentsh.tar.gz');
    expect(cmds.some(c => c.includes('shasum'))).toBe(true);
  });

  it('includes openssl fallback', () => {
    const cmds = buildVerifyCommand('/tmp/agentsh.tar.gz');
    expect(cmds.some(c => c.includes('openssl'))).toBe(true);
  });
});
```

**Step 2: Run tests to verify failure**

```bash
npx vitest run src/core/integrity.test.ts
```

**Step 3: Implement integrity.ts**

```ts
import { IntegrityError } from './errors.js';

export const PINNED_VERSION = '0.14.0';

export const CHECKSUMS: Record<string, Record<string, string>> = {
  '0.14.0': {
    linux_amd64: '2ab8ba0d6637fe1a5badf840c3db197161a6f9865d721ed216029d229b1b9bbc',
    linux_arm64: '929d18dd9fe36e9b2fa830d7ae64b4fb481853e743ade8674fcfcdc73470ed53',
  },
};

export function getChecksum(
  version: string,
  arch: string,
  override?: string,
): string {
  if (override) return override;
  const versionMap = CHECKSUMS[version];
  if (!versionMap?.[arch]) {
    throw new IntegrityError({
      expected: `pinned checksum for v${version} ${arch}`,
      actual: 'none',
      message: `No pinned checksum for agentsh v${version}. Provide \`agentshChecksum\` explicitly or use \`skipIntegrityCheck: true\`.`,
    });
  }
  return versionMap[arch];
}

export function buildVerifyCommand(filePath: string): string[] {
  // Returns array of commands to try in order
  return [
    `sha256sum '${filePath}' | awk '{print $1}'`,
    `shasum -a 256 '${filePath}' | awk '{print $1}'`,
    `openssl dgst -sha256 '${filePath}' | awk '{print $NF}'`,
  ];
}

export function binaryUrl(version: string, arch: string, overrideUrl?: string): string {
  if (overrideUrl) return overrideUrl;
  return `https://github.com/canyonroad/agentsh/releases/download/v${version}/agentsh_${arch}.tar.gz`;
}
```

**Step 4: Run tests**

```bash
npx vitest run src/core/integrity.test.ts
```

**Step 5: Commit**

```bash
git add src/core/integrity.ts src/core/integrity.test.ts
git commit -m "feat: integrity verification — checksums, verify commands, binary URL"
```

---

### Task 9: Shell Escape Utility

**Files:**
- Create: `src/core/shell.ts`
- Create: `src/core/shell.test.ts`

**Step 1: Write failing tests**

```ts
import { describe, it, expect } from 'vitest';
import { shellEscape } from './shell.js';

describe('shellEscape', () => {
  it('joins simple command and args', () => {
    expect(shellEscape('ls', ['-la', '/workspace'])).toBe("ls -la /workspace");
  });

  it('quotes args with spaces', () => {
    expect(shellEscape('echo', ['hello world'])).toBe("echo 'hello world'");
  });

  it('escapes single quotes in args', () => {
    expect(shellEscape('echo', ["it's"])).toBe("echo 'it'\\''s'");
  });

  it('quotes args with shell metacharacters', () => {
    expect(shellEscape('echo', ['$HOME'])).toBe("echo '$HOME'");
    expect(shellEscape('echo', ['a;b'])).toBe("echo 'a;b'");
    expect(shellEscape('echo', ['a|b'])).toBe("echo 'a|b'");
  });

  it('handles empty args array', () => {
    expect(shellEscape('ls', [])).toBe('ls');
    expect(shellEscape('ls')).toBe('ls');
  });

  it('does not quote safe args', () => {
    expect(shellEscape('git', ['status', '--short'])).toBe('git status --short');
  });
});
```

**Step 2: Run tests to verify failure**

```bash
npx vitest run src/core/shell.test.ts
```

**Step 3: Implement shell.ts**

Single-quote wrapping for unsafe characters. A string is "safe" if it matches `/^[a-zA-Z0-9._\-\/=:@]+$/`. Otherwise, wrap in single quotes with `'` escaped as `'\''`.

**Step 4: Run tests**

```bash
npx vitest run src/core/shell.test.ts
```

**Step 5: Commit**

```bash
git add src/core/shell.ts src/core/shell.test.ts
git commit -m "feat: shellEscape utility for safe command construction"
```

---

### Task 10: Server Config Generation

**Files:**
- Create: `src/core/config.ts`
- Create: `src/core/config.test.ts`

**Step 1: Write failing tests**

```ts
import { describe, it, expect } from 'vitest';
import yaml from 'js-yaml';
import { generateServerConfig } from './config.js';

describe('generateServerConfig', () => {
  it('generates valid YAML with policy dirs', () => {
    const result = generateServerConfig({ workspace: '/workspace' });
    const parsed = yaml.load(result) as any;
    expect(parsed.policies.system_dir).toBe('/etc/agentsh/system');
    expect(parsed.policies.dir).toBe('/etc/agentsh');
    expect(parsed.policies.default).toBe('policy');
  });

  it('includes workspace path', () => {
    const result = generateServerConfig({ workspace: '/home/daytona' });
    const parsed = yaml.load(result) as any;
    expect(parsed.workspace).toBe('/home/daytona');
  });

  it('includes watchtower when provided', () => {
    const result = generateServerConfig({
      workspace: '/workspace',
      watchtower: 'https://watchtower.example.com',
    });
    const parsed = yaml.load(result) as any;
    expect(parsed.watchtower).toBe('https://watchtower.example.com');
  });

  it('omits watchtower when not provided', () => {
    const result = generateServerConfig({ workspace: '/workspace' });
    const parsed = yaml.load(result) as any;
    expect(parsed.watchtower).toBeUndefined();
  });

  it('includes enforceRedirects when true', () => {
    const result = generateServerConfig({
      workspace: '/workspace',
      enforceRedirects: true,
    });
    const parsed = yaml.load(result) as any;
    expect(parsed.enforce_redirects).toBe(true);
  });

  it('includes realPaths when true', () => {
    const result = generateServerConfig({
      workspace: '/workspace',
      realPaths: true,
    });
    const parsed = yaml.load(result) as any;
    expect(parsed.real_paths).toBe(true);
  });
});
```

**Step 2: Run, fail, implement, pass**

```bash
npx vitest run src/core/config.test.ts
```

**Step 3: Implement config.ts**

Builds a config object and serializes to YAML. The config references the policy directories per SPEC-v2.md Section 9.4.

**Step 4: Commit**

```bash
git add src/core/config.ts src/core/config.test.ts
git commit -m "feat: agentsh server config generation"
```

---

### Task 11: Provisioning

**Ref:** SPEC-v2.md Section 10

**Files:**
- Create: `src/core/provision.ts`
- Create: `src/core/provision.test.ts`

This is the largest task. The provisioning function orchestrates the 14-step flow.

**Step 1: Write failing tests**

Create a `createMockAdapter()` helper that returns a `SandboxAdapter` with `vi.fn()` methods and configurable responses:

```ts
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { provision } from './provision.js';
import type { SandboxAdapter, ExecResult, SecureConfig } from './types.js';

function ok(stdout = ''): ExecResult {
  return { stdout, stderr: '', exitCode: 0 };
}

function createMockAdapter(overrides?: Partial<Record<string, ExecResult>>): SandboxAdapter {
  const responses: Record<string, ExecResult> = {
    'test -f /usr/local/bin/agentsh': { stdout: '', stderr: '', exitCode: 1 }, // not preinstalled
    'uname -m': ok('x86_64'),
    'curl': ok(),
    'tar': ok(),
    'sha256sum': ok('2ab8ba0d6637fe1a5badf840c3db197161a6f9865d721ed216029d229b1b9bbc  /tmp/agentsh.tar.gz'),
    'install': ok(),
    'agentsh detect': ok(JSON.stringify({ mode: 'full' })),
    'agentsh shim': ok(),
    'mkdir': ok(),
    'find': ok(),
    'chown': ok(),
    'agentsh server': ok(),
    'agentsh health': ok(),
    'agentsh session create': ok(JSON.stringify({ session_id: 'test-session-123' })),
    ...overrides,
  };

  return {
    exec: vi.fn(async (cmd: string, args?: string[]) => {
      const fullCmd = [cmd, ...(args ?? [])].join(' ');
      // Match by prefix
      for (const [key, val] of Object.entries(responses)) {
        if (fullCmd.includes(key)) return val;
      }
      return ok();
    }),
    writeFile: vi.fn(async () => {}),
    readFile: vi.fn(async () => ''),
  };
}
```

Tests to write:

```ts
describe('provision', () => {
  it('completes full download flow and returns session ID + security mode', async () => {
    const adapter = createMockAdapter();
    const result = await provision(adapter, { workspace: '/workspace' });
    expect(result.sessionId).toBe('test-session-123');
    expect(result.securityMode).toBe('full');
  });

  it('skips download when preinstalled', async () => {
    const adapter = createMockAdapter({
      'test -f /usr/local/bin/agentsh': ok(), // exists
    });
    const result = await provision(adapter, {
      workspace: '/workspace',
      installStrategy: 'preinstalled',
    });
    expect(adapter.exec).not.toHaveBeenCalledWith(
      expect.anything(),
      expect.arrayContaining(['curl']),
      expect.anything(),
    );
    expect(result.sessionId).toBe('test-session-123');
  });

  it('throws ProvisioningError when binary not found with preinstalled strategy', async () => {
    const adapter = createMockAdapter(); // binary doesn't exist
    await expect(
      provision(adapter, { installStrategy: 'preinstalled', workspace: '/workspace' }),
    ).rejects.toThrow('preinstalled');
  });

  it('writes system policy and user policy', async () => {
    const adapter = createMockAdapter();
    await provision(adapter, { workspace: '/workspace' });
    expect(adapter.writeFile).toHaveBeenCalledWith(
      '/etc/agentsh/system/policy.yml',
      expect.stringContaining('_system-protect-config'),
      expect.objectContaining({ sudo: true }),
    );
    expect(adapter.writeFile).toHaveBeenCalledWith(
      '/etc/agentsh/policy.yml',
      expect.any(String),
      expect.objectContaining({ sudo: true }),
    );
  });

  it('writes server config', async () => {
    const adapter = createMockAdapter();
    await provision(adapter, { workspace: '/workspace' });
    expect(adapter.writeFile).toHaveBeenCalledWith(
      '/etc/agentsh/config.yml',
      expect.any(String),
      expect.objectContaining({ sudo: true }),
    );
  });

  it('sets file permissions after writing policy', async () => {
    const adapter = createMockAdapter();
    await provision(adapter, { workspace: '/workspace' });
    // Verify chmod and chown were called
    const execCalls = (adapter.exec as ReturnType<typeof vi.fn>).mock.calls
      .map(c => [c[0], ...(c[1] ?? [])].join(' '));
    expect(execCalls.some(c => c.includes('chmod 555'))).toBe(true);
    expect(execCalls.some(c => c.includes('chmod 444'))).toBe(true);
    expect(execCalls.some(c => c.includes('chown'))).toBe(true);
  });

  it('starts server detached with sudo', async () => {
    const adapter = createMockAdapter();
    await provision(adapter, { workspace: '/workspace' });
    expect(adapter.exec).toHaveBeenCalledWith(
      'agentsh',
      expect.arrayContaining(['server']),
      expect.objectContaining({ detached: true, sudo: true }),
    );
  });

  it('throws ProvisioningError on health check failure', async () => {
    const adapter = createMockAdapter({
      'agentsh health': { stdout: '', stderr: 'not ready', exitCode: 1 },
    });
    await expect(
      provision(adapter, { workspace: '/workspace' }),
    ).rejects.toThrow('ProvisioningError');
  });

  it('throws IntegrityError on checksum mismatch', async () => {
    const adapter = createMockAdapter({
      'sha256sum': ok('badhash  /tmp/agentsh.tar.gz'),
    });
    await expect(
      provision(adapter, { workspace: '/workspace' }),
    ).rejects.toThrow('IntegrityError');
  });

  it('throws ProvisioningError when minimum security mode not met', async () => {
    const adapter = createMockAdapter({
      'agentsh detect': ok(JSON.stringify({ mode: 'minimal' })),
    });
    await expect(
      provision(adapter, {
        workspace: '/workspace',
        minimumSecurityMode: 'landlock',
      }),
    ).rejects.toThrow('ProvisioningError');
  });

  it('uses upload strategy', async () => {
    const adapter = createMockAdapter();
    await provision(adapter, {
      workspace: '/workspace',
      installStrategy: 'upload',
    });
    expect(adapter.writeFile).toHaveBeenCalledWith(
      '/tmp/agentsh',
      expect.any(Buffer),
    );
  });

  it('maps uname x86_64 to linux_amd64', async () => {
    const adapter = createMockAdapter({
      'uname -m': ok('x86_64'),
    });
    await provision(adapter, { workspace: '/workspace' });
    const execCalls = (adapter.exec as ReturnType<typeof vi.fn>).mock.calls
      .map(c => [c[0], ...(c[1] ?? [])].join(' '));
    const curlCall = execCalls.find(c => c.includes('curl'));
    expect(curlCall).toContain('linux_amd64');
  });

  it('maps uname aarch64 to linux_arm64', async () => {
    const adapter = createMockAdapter({
      'uname -m': ok('aarch64'),
    });
    await provision(adapter, { workspace: '/workspace' });
    const execCalls = (adapter.exec as ReturnType<typeof vi.fn>).mock.calls
      .map(c => [c[0], ...(c[1] ?? [])].join(' '));
    const curlCall = execCalls.find(c => c.includes('curl'));
    expect(curlCall).toContain('linux_arm64');
  });

  it('uses agentDefault policy when none specified', async () => {
    const adapter = createMockAdapter();
    await provision(adapter, { workspace: '/workspace' });
    const writeFileCalls = (adapter.writeFile as ReturnType<typeof vi.fn>).mock.calls;
    const policyWrite = writeFileCalls.find(c => c[0] === '/etc/agentsh/policy.yml');
    expect(policyWrite).toBeDefined();
    // Should contain agentDefault rules
    expect(policyWrite![1]).toContain('registry.npmjs.org');
  });
});
```

**Step 2: Run tests to verify failure**

```bash
npx vitest run src/core/provision.test.ts
```

**Step 3: Implement provision.ts**

```ts
import type { SandboxAdapter, SecureConfig, SecurityMode } from './types.js';
import { ProvisioningError, IntegrityError } from './errors.js';
import { getChecksum, buildVerifyCommand, binaryUrl, PINNED_VERSION } from './integrity.js';
import { serializePolicy, systemPolicyYaml } from '../policies/serialize.js';
import { agentDefault } from '../policies/presets.js';
import { validatePolicy } from '../policies/schema.js';
import { generateServerConfig } from './config.js';

const SECURITY_MODE_ORDER: SecurityMode[] = ['full', 'landlock', 'landlock-only', 'minimal'];

export interface ProvisionResult {
  sessionId: string;
  securityMode: SecurityMode;
}

export async function provision(
  adapter: SandboxAdapter,
  config: SecureConfig,
): Promise<ProvisionResult> {
  const workspace = config.workspace ?? '/workspace';
  const version = config.agentshVersion ?? PINNED_VERSION;
  const strategy = config.installStrategy ?? 'download';
  const policy = config.policy ?? agentDefault();

  // Validate policy
  validatePolicy(policy);

  // PHASE 1 — Binary Installation
  if (strategy !== 'preinstalled' || !(await fileExists(adapter, '/usr/local/bin/agentsh'))) {
    if (strategy === 'preinstalled') {
      throw new ProvisioningError({ phase: 'install', command: 'fileExists', stderr: 'agentsh binary not found at /usr/local/bin/agentsh with preinstalled strategy' });
    }
    await installBinary(adapter, config, version);
  }

  // Detect security mode
  const securityMode = await detectSecurityMode(adapter, config);

  // Install shell shim
  await execOrThrow(adapter, 'agentsh', ['shim', 'install-shell'], { sudo: true }, 'install');

  // PHASE 2 — Policy and Config
  await adapter.exec('mkdir', ['-p', '/etc/agentsh/system'], { sudo: true });
  await adapter.writeFile('/etc/agentsh/system/policy.yml', systemPolicyYaml(), { sudo: true });
  await adapter.writeFile('/etc/agentsh/policy.yml', serializePolicy(policy), { sudo: true });
  await adapter.writeFile('/etc/agentsh/config.yml', generateServerConfig({ workspace, watchtower: config.watchtower, enforceRedirects: config.enforceRedirects, realPaths: config.realPaths }), { sudo: true });

  // Set permissions
  await adapter.exec('find', ['/etc/agentsh', '-type', 'd', '-exec', 'chmod', '555', '{}', '+'], { sudo: true });
  await adapter.exec('find', ['/etc/agentsh', '-type', 'f', '-exec', 'chmod', '444', '{}', '+'], { sudo: true });
  await adapter.exec('chown', ['-R', 'root:root', '/etc/agentsh/'], { sudo: true });

  // PHASE 3 — Server Startup
  await adapter.exec('agentsh', ['server', '--config', '/etc/agentsh/config.yml'], { detached: true, sudo: true });
  await healthCheck(adapter);
  const sessionId = await createSession(adapter, workspace);

  // PHASE 4 — Handoff
  return { sessionId, securityMode };
}
```

Implement the helper functions: `installBinary` (handles download/upload strategies with curl→wget fallback and checksum verification), `detectSecurityMode` (parses `agentsh detect --json`), `healthCheck` (polls up to 10 times with 500ms backoff), `createSession` (parses session ID from JSON output), `fileExists` (uses adapter.fileExists or falls back to exec test -f).

**Step 4: Run tests**

```bash
npx vitest run src/core/provision.test.ts
```

Note: The upload strategy test may need adjustment since it involves host-side binary download. For the mock test, the adapter.writeFile call with a Buffer is sufficient to verify the flow.

**Step 5: Commit**

```bash
git add src/core/provision.ts src/core/provision.test.ts
git commit -m "feat: provisioning flow — 4 phases, 14 steps"
```

---

### Task 12: Runtime (SecuredSandbox Implementation)

**Ref:** SPEC-v2.md Section 8

**Files:**
- Create: `src/core/runtime.ts`
- Create: `src/core/runtime.test.ts`

**Step 1: Write failing tests**

```ts
import { describe, it, expect, vi } from 'vitest';
import { createSecuredSandbox } from './runtime.js';
import type { SandboxAdapter } from './types.js';
import { RuntimeError } from './errors.js';

function createMockAdapter(): SandboxAdapter {
  return {
    exec: vi.fn(async () => ({ stdout: '', stderr: '', exitCode: 0 })),
    writeFile: vi.fn(async () => {}),
    readFile: vi.fn(async () => ''),
    stop: vi.fn(async () => {}),
  };
}

describe('SecuredSandbox', () => {
  describe('exec', () => {
    it('routes through agentsh exec with session ID', async () => {
      const adapter = createMockAdapter();
      const sandbox = createSecuredSandbox(adapter, 'sid-123', 'full');
      await sandbox.exec('ls /workspace');
      expect(adapter.exec).toHaveBeenCalledWith(
        'agentsh',
        ['exec', '--output', 'json', 'sid-123', '--', 'bash', '-c', 'ls /workspace'],
        undefined,
      );
    });

    it('passes cwd when provided', async () => {
      const adapter = createMockAdapter();
      const sandbox = createSecuredSandbox(adapter, 'sid-123', 'full');
      await sandbox.exec('ls', { cwd: '/workspace/src' });
      expect(adapter.exec).toHaveBeenCalledWith(
        'agentsh',
        expect.anything(),
        expect.objectContaining({ cwd: '/workspace/src' }),
      );
    });

    it('returns ExecResult from agentsh', async () => {
      const adapter = createMockAdapter();
      (adapter.exec as ReturnType<typeof vi.fn>).mockResolvedValue({
        stdout: 'file1.ts\nfile2.ts',
        stderr: '',
        exitCode: 0,
      });
      const sandbox = createSecuredSandbox(adapter, 'sid-123', 'full');
      const result = await sandbox.exec('ls /workspace');
      expect(result.stdout).toBe('file1.ts\nfile2.ts');
      expect(result.exitCode).toBe(0);
    });

    it('returns denial as structured result, does NOT throw', async () => {
      const adapter = createMockAdapter();
      (adapter.exec as ReturnType<typeof vi.fn>).mockResolvedValue({
        stdout: '',
        stderr: 'denied by policy: env command is blocked',
        exitCode: 1,
      });
      const sandbox = createSecuredSandbox(adapter, 'sid-123', 'full');
      const result = await sandbox.exec('env');
      expect(result.exitCode).toBe(1);
      expect(result.stderr).toContain('denied by policy');
    });

    it('throws RuntimeError on transport failure (exit code 127)', async () => {
      const adapter = createMockAdapter();
      (adapter.exec as ReturnType<typeof vi.fn>).mockResolvedValue({
        stdout: '',
        stderr: 'agentsh: command not found',
        exitCode: 127,
      });
      const sandbox = createSecuredSandbox(adapter, 'sid-123', 'full');
      await expect(sandbox.exec('ls')).rejects.toThrow(RuntimeError);
    });
  });

  describe('writeFile', () => {
    it('routes through agentsh exec with base64-encoded content', async () => {
      const adapter = createMockAdapter();
      const sandbox = createSecuredSandbox(adapter, 'sid-123', 'full');
      const result = await sandbox.writeFile('/workspace/test.txt', 'hello world');
      expect(result.success).toBe(true);
      expect(result.path).toBe('/workspace/test.txt');
      // Verify it used agentsh exec with base64
      expect(adapter.exec).toHaveBeenCalledWith(
        'agentsh',
        expect.arrayContaining(['exec', 'sid-123']),
        undefined,
      );
    });

    it('returns failure on policy denial', async () => {
      const adapter = createMockAdapter();
      (adapter.exec as ReturnType<typeof vi.fn>).mockResolvedValue({
        stdout: '',
        stderr: 'denied by policy',
        exitCode: 1,
      });
      const sandbox = createSecuredSandbox(adapter, 'sid-123', 'full');
      const result = await sandbox.writeFile('/etc/passwd', 'evil');
      expect(result.success).toBe(false);
      expect('error' in result && result.error).toContain('denied');
    });
  });

  describe('readFile', () => {
    it('routes through agentsh exec cat', async () => {
      const adapter = createMockAdapter();
      (adapter.exec as ReturnType<typeof vi.fn>).mockResolvedValue({
        stdout: 'file contents here',
        stderr: '',
        exitCode: 0,
      });
      const sandbox = createSecuredSandbox(adapter, 'sid-123', 'full');
      const result = await sandbox.readFile('/workspace/test.txt');
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.content).toBe('file contents here');
      }
    });

    it('returns failure on denial', async () => {
      const adapter = createMockAdapter();
      (adapter.exec as ReturnType<typeof vi.fn>).mockResolvedValue({
        stdout: '',
        stderr: 'denied by policy',
        exitCode: 1,
      });
      const sandbox = createSecuredSandbox(adapter, 'sid-123', 'full');
      const result = await sandbox.readFile('~/.ssh/id_rsa');
      expect(result.success).toBe(false);
    });
  });

  describe('stop', () => {
    it('calls adapter.stop if available', async () => {
      const adapter = createMockAdapter();
      const sandbox = createSecuredSandbox(adapter, 'sid-123', 'full');
      await sandbox.stop();
      expect(adapter.stop).toHaveBeenCalled();
    });

    it('does not throw if adapter has no stop method', async () => {
      const adapter = createMockAdapter();
      delete adapter.stop;
      const sandbox = createSecuredSandbox(adapter, 'sid-123', 'full');
      await expect(sandbox.stop()).resolves.not.toThrow();
    });
  });

  describe('properties', () => {
    it('exposes sessionId', () => {
      const adapter = createMockAdapter();
      const sandbox = createSecuredSandbox(adapter, 'sid-123', 'full');
      expect(sandbox.sessionId).toBe('sid-123');
    });

    it('exposes securityMode', () => {
      const adapter = createMockAdapter();
      const sandbox = createSecuredSandbox(adapter, 'sid-123', 'landlock');
      expect(sandbox.securityMode).toBe('landlock');
    });
  });
});
```

**Step 2: Run tests to verify failure**

```bash
npx vitest run src/core/runtime.test.ts
```

**Step 3: Implement runtime.ts**

```ts
import type { SandboxAdapter, SecuredSandbox, SecurityMode, ExecResult, ReadFileResult, WriteFileResult } from './types.js';
import { RuntimeError } from './errors.js';

export function createSecuredSandbox(
  adapter: SandboxAdapter,
  sessionId: string,
  securityMode: SecurityMode,
): SecuredSandbox {
  function isTransportFailure(result: ExecResult): boolean {
    return result.exitCode === 127 && result.stderr.includes('agentsh');
  }

  return {
    sessionId,
    securityMode,

    async exec(command, opts) {
      const args = ['exec', '--output', 'json', sessionId, '--', 'bash', '-c', command];
      const result = await adapter.exec('agentsh', args, opts?.cwd ? { cwd: opts.cwd } : undefined);
      if (isTransportFailure(result)) {
        throw new RuntimeError({ sessionId, command, stderr: result.stderr });
      }
      return result;
    },

    async writeFile(path, content) {
      const b64 = Buffer.from(content, 'utf-8').toString('base64');
      const args = [
        'exec', sessionId, '--',
        'sh', '-c', 'printf "%s" "$1" | base64 -d > "$2"', '_', b64, path,
      ];
      const result = await adapter.exec('agentsh', args);
      if (isTransportFailure(result)) {
        throw new RuntimeError({ sessionId, command: `writeFile ${path}`, stderr: result.stderr });
      }
      if (result.exitCode !== 0) {
        return { success: false, path, error: result.stderr || 'writeFile failed' };
      }
      return { success: true, path };
    },

    async readFile(path) {
      const args = ['exec', sessionId, '--', 'cat', path];
      const result = await adapter.exec('agentsh', args);
      if (isTransportFailure(result)) {
        throw new RuntimeError({ sessionId, command: `readFile ${path}`, stderr: result.stderr });
      }
      if (result.exitCode !== 0) {
        return { success: false, path, error: result.stderr || 'readFile failed' };
      }
      return { success: true, path, content: result.stdout };
    },

    async stop() {
      await adapter.stop?.();
    },
  };
}
```

**Step 4: Run tests**

```bash
npx vitest run src/core/runtime.test.ts
```

**Step 5: Commit**

```bash
git add src/core/runtime.ts src/core/runtime.test.ts
git commit -m "feat: SecuredSandbox runtime — exec, writeFile, readFile through agentsh"
```

---

### Task 13: Adapters

**Ref:** SPEC-v2.md Section 7

**Files:**
- Create: `src/adapters/vercel.ts`
- Create: `src/adapters/e2b.ts`
- Create: `src/adapters/daytona.ts`
- Create: `src/adapters/index.ts`
- Create: `src/adapters/adapters.test.ts`

Each adapter is thin (~15-30 lines). They translate provider APIs to `SandboxAdapter`. Since we don't have provider SDKs installed (they're optional peer deps), adapters use type-only imports and dynamic imports.

**Step 1: Write failing tests**

Test the adapters by mocking the provider SDK objects. Each test creates a fake provider sandbox object and verifies the adapter correctly translates calls.

```ts
import { describe, it, expect, vi } from 'vitest';
import { vercel } from './vercel.js';
import { e2b } from './e2b.js';
import { daytona } from './daytona.js';

describe('vercel adapter', () => {
  it('maps exec to sandbox.runCommand', async () => {
    const mockSandbox = {
      runCommand: vi.fn(async () => ({
        stdout: () => 'output',
        stderr: () => '',
        exitCode: 0,
      })),
      writeFiles: vi.fn(async () => {}),
      readFile: vi.fn(async () => 'content'),
      stop: vi.fn(async () => {}),
    };
    const adapter = vercel(mockSandbox as any);
    const result = await adapter.exec('ls', ['-la'], { cwd: '/workspace' });
    expect(mockSandbox.runCommand).toHaveBeenCalledWith(
      expect.objectContaining({ cmd: 'ls', args: ['-la'], cwd: '/workspace' }),
    );
    expect(result.stdout).toBe('output');
  });

  it('maps writeFile to sandbox.writeFiles', async () => {
    const mockSandbox = {
      runCommand: vi.fn(),
      writeFiles: vi.fn(async () => {}),
      readFile: vi.fn(),
      stop: vi.fn(),
    };
    const adapter = vercel(mockSandbox as any);
    await adapter.writeFile('/workspace/test.txt', 'hello');
    expect(mockSandbox.writeFiles).toHaveBeenCalledWith([
      { path: '/workspace/test.txt', content: 'hello' },
    ]);
  });

  it('maps readFile to sandbox.readFile', async () => {
    const mockSandbox = {
      runCommand: vi.fn(),
      writeFiles: vi.fn(),
      readFile: vi.fn(async () => 'file content'),
      stop: vi.fn(),
    };
    const adapter = vercel(mockSandbox as any);
    const result = await adapter.readFile('/workspace/test.txt');
    expect(result).toBe('file content');
  });

  it('maps stop to sandbox.stop', async () => {
    const mockSandbox = {
      runCommand: vi.fn(),
      writeFiles: vi.fn(),
      readFile: vi.fn(),
      stop: vi.fn(async () => {}),
    };
    const adapter = vercel(mockSandbox as any);
    await adapter.stop!();
    expect(mockSandbox.stop).toHaveBeenCalled();
  });
});

describe('e2b adapter', () => {
  it('maps exec to sandbox.commands.run with shell escaping', async () => {
    const mockSandbox = {
      commands: {
        run: vi.fn(async () => ({
          stdout: 'output',
          stderr: '',
          exitCode: 0,
        })),
      },
      files: {
        write: vi.fn(async () => {}),
        read: vi.fn(async () => 'content'),
        list: vi.fn(async () => []),
      },
      kill: vi.fn(async () => {}),
    };
    const adapter = e2b(mockSandbox as any);
    const result = await adapter.exec('echo', ['hello world']);
    // Should be shell-escaped
    expect(mockSandbox.commands.run).toHaveBeenCalledWith(
      expect.stringContaining('echo'),
      expect.any(Object),
    );
    expect(result.stdout).toBe('output');
  });

  it('uses root user when sudo is true', async () => {
    const mockSandbox = {
      commands: { run: vi.fn(async () => ({ stdout: '', stderr: '', exitCode: 0 })) },
      files: { write: vi.fn(), read: vi.fn(), list: vi.fn() },
      kill: vi.fn(),
    };
    const adapter = e2b(mockSandbox as any);
    await adapter.exec('chmod', ['755', '/tmp/agentsh'], { sudo: true });
    expect(mockSandbox.commands.run).toHaveBeenCalledWith(
      expect.any(String),
      expect.objectContaining({ user: 'root' }),
    );
  });
});

describe('daytona adapter', () => {
  it('maps exec to sandbox.process.executeCommand', async () => {
    const mockSandbox = {
      process: {
        executeCommand: vi.fn(async () => ({
          exitCode: 0,
          result: 'output',
        })),
      },
      fs: {
        uploadFile: vi.fn(async () => {}),
        downloadFile: vi.fn(async () => 'content'),
      },
    };
    const adapter = daytona(mockSandbox as any);
    const result = await adapter.exec('ls', ['-la']);
    expect(mockSandbox.process.executeCommand).toHaveBeenCalled();
    expect(result.stdout).toBe('output');
  });
});
```

**Step 2: Run tests to verify failure**

```bash
npx vitest run src/adapters/adapters.test.ts
```

**Step 3: Implement adapters**

Each adapter is a function that takes the provider object and returns `SandboxAdapter`. Key implementation details:

- **vercel.ts**: Wraps `sandbox.runCommand`, `sandbox.writeFiles`, `sandbox.readFile`, `sandbox.stop`. The `runCommand` result has `stdout()` and `stderr()` as methods (Vercel API).
- **e2b.ts**: Uses `shellEscape` from `../core/shell.js` for safe command concatenation. Maps `sudo` to `user: 'root'`. Wraps detached commands with `nohup ... &`.
- **daytona.ts**: Uses unique temp file per exec for stderr splitting. Wraps `sandbox.process.executeCommand`.

**adapters/index.ts**:
```ts
export { vercel } from './vercel.js';
export { e2b } from './e2b.js';
export { daytona } from './daytona.js';
```

**Step 4: Run tests**

```bash
npx vitest run src/adapters/adapters.test.ts
```

**Step 5: Commit**

```bash
git add src/adapters/
git commit -m "feat: adapters — vercel, e2b, daytona"
```

---

### Task 14: Main API — secureSandbox() & createSandbox()

**Ref:** SPEC-v2.md Sections 5.1, 5.2

**Files:**
- Create: `src/api.ts`
- Create: `src/api.test.ts`

**Step 1: Write failing tests**

```ts
import { describe, it, expect, vi } from 'vitest';
import { secureSandbox } from './api.js';
import type { SandboxAdapter } from './core/types.js';

function createFullMockAdapter(): SandboxAdapter {
  // Same mock pattern as provision.test.ts — responds to all provisioning commands
  return {
    exec: vi.fn(async (cmd: string, args?: string[]) => {
      const full = [cmd, ...(args ?? [])].join(' ');
      if (full.includes('test -f')) return { stdout: '', stderr: '', exitCode: 1 };
      if (full.includes('uname')) return { stdout: 'x86_64', stderr: '', exitCode: 0 };
      if (full.includes('sha256sum')) return { stdout: '2ab8ba0d6637fe1a5badf840c3db197161a6f9865d721ed216029d229b1b9bbc  /tmp/f', stderr: '', exitCode: 0 };
      if (full.includes('agentsh detect')) return { stdout: JSON.stringify({ mode: 'full' }), stderr: '', exitCode: 0 };
      if (full.includes('agentsh session create')) return { stdout: JSON.stringify({ session_id: 'sid-test' }), stderr: '', exitCode: 0 };
      return { stdout: '', stderr: '', exitCode: 0 };
    }),
    writeFile: vi.fn(async () => {}),
    readFile: vi.fn(async () => ''),
    stop: vi.fn(async () => {}),
  };
}

describe('secureSandbox', () => {
  it('returns a SecuredSandbox', async () => {
    const adapter = createFullMockAdapter();
    const sandbox = await secureSandbox(adapter);
    expect(sandbox.sessionId).toBe('sid-test');
    expect(sandbox.securityMode).toBe('full');
    expect(typeof sandbox.exec).toBe('function');
    expect(typeof sandbox.writeFile).toBe('function');
    expect(typeof sandbox.readFile).toBe('function');
    expect(typeof sandbox.stop).toBe('function');
  });

  it('uses agentDefault policy when none specified', async () => {
    const adapter = createFullMockAdapter();
    await secureSandbox(adapter);
    const writeFileCalls = (adapter.writeFile as ReturnType<typeof vi.fn>).mock.calls;
    const policyWrite = writeFileCalls.find((c: any) => c[0] === '/etc/agentsh/policy.yml');
    expect(policyWrite![1]).toContain('registry.npmjs.org');
  });

  it('validates custom policy', async () => {
    const adapter = createFullMockAdapter();
    await expect(
      secureSandbox(adapter, {
        policy: { file: [{ invalid: true }] } as any,
      }),
    ).rejects.toThrow('PolicyValidationError');
  });

  it('runtime exec goes through agentsh', async () => {
    const adapter = createFullMockAdapter();
    const sandbox = await secureSandbox(adapter);
    await sandbox.exec('ls');
    const lastExecCall = (adapter.exec as ReturnType<typeof vi.fn>).mock.calls.at(-1);
    expect(lastExecCall![0]).toBe('agentsh');
    expect(lastExecCall![1]).toContain('exec');
  });
});
```

**Step 2: Run tests to verify failure**

```bash
npx vitest run src/api.test.ts
```

**Step 3: Implement api.ts**

```ts
import type { SandboxAdapter, SecuredSandbox, SecureConfig, CreateSandboxConfig } from './core/types.js';
import { MissingPeerDependencyError } from './core/errors.js';
import { provision } from './core/provision.js';
import { createSecuredSandbox } from './core/runtime.js';

export async function secureSandbox(
  adapter: SandboxAdapter,
  config?: SecureConfig,
): Promise<SecuredSandbox> {
  const resolvedConfig = config ?? {};
  const { sessionId, securityMode } = await provision(adapter, {
    workspace: '/workspace',
    ...resolvedConfig,
  });
  return createSecuredSandbox(adapter, sessionId, securityMode);
}

export async function createSandbox(
  config?: CreateSandboxConfig,
): Promise<SecuredSandbox> {
  let Sandbox: any;
  try {
    const mod = await import('@vercel/sandbox');
    Sandbox = mod.Sandbox;
  } catch {
    throw new MissingPeerDependencyError({
      packageName: '@vercel/sandbox',
      versionRange: '^1.0.0',
    });
  }

  const { runtime = 'node24', timeout = 300_000, vcpus = 2, snapshot, ...secureConfig } = config ?? {};

  const createOpts: Record<string, unknown> = { runtime, timeout, vcpus };
  if (snapshot) createOpts.snapshot = snapshot;

  const sandbox = await Sandbox.create(createOpts);
  const { vercel } = await import('./adapters/vercel.js');

  return secureSandbox(vercel(sandbox), {
    ...secureConfig,
    installStrategy: snapshot ? 'preinstalled' : secureConfig.installStrategy,
  });
}
```

**Step 4: Run tests**

```bash
npx vitest run src/api.test.ts
```

**Step 5: Commit**

```bash
git add src/api.ts src/api.test.ts
git commit -m "feat: secureSandbox() and createSandbox() main API"
```

---

### Task 15: Testing Utilities

**Ref:** SPEC-v2.md Section 13

**Files:**
- Create: `src/testing/index.ts`
- Create: `src/testing/testing.test.ts`

**Step 1: Write failing tests**

```ts
import { describe, it, expect } from 'vitest';
import { mockSecuredSandbox } from './index.js';

describe('mockSecuredSandbox', () => {
  it('returns a SecuredSandbox with sessionId and securityMode', () => {
    const sandbox = mockSecuredSandbox({});
    expect(sandbox.sessionId).toBeDefined();
    expect(sandbox.securityMode).toBe('full');
  });

  it('exec returns matching command response', async () => {
    const sandbox = mockSecuredSandbox({
      commands: {
        'ls /workspace': { stdout: 'file1.ts', stderr: '', exitCode: 0 },
      },
    });
    const result = await sandbox.exec('ls /workspace');
    expect(result.stdout).toBe('file1.ts');
    expect(result.exitCode).toBe(0);
  });

  it('exec returns exitCode 1 for unmatched commands', async () => {
    const sandbox = mockSecuredSandbox({ commands: {} });
    const result = await sandbox.exec('unknown-command');
    expect(result.exitCode).toBe(1);
  });

  it('readFile returns matching file content', async () => {
    const sandbox = mockSecuredSandbox({
      files: { '/workspace/index.ts': 'console.log("hi")' },
    });
    const result = await sandbox.readFile('/workspace/index.ts');
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.content).toBe('console.log("hi")');
    }
  });

  it('readFile returns failure for unknown path', async () => {
    const sandbox = mockSecuredSandbox({ files: {} });
    const result = await sandbox.readFile('/etc/shadow');
    expect(result.success).toBe(false);
  });

  it('writeFile succeeds for commands that match', async () => {
    const sandbox = mockSecuredSandbox({});
    const result = await sandbox.writeFile('/workspace/test.txt', 'hello');
    expect(result.success).toBe(true);
  });

  it('writeFile records written files for later readFile', async () => {
    const sandbox = mockSecuredSandbox({});
    await sandbox.writeFile('/workspace/test.txt', 'hello');
    const result = await sandbox.readFile('/workspace/test.txt');
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.content).toBe('hello');
    }
  });

  it('stop does not throw', async () => {
    const sandbox = mockSecuredSandbox({});
    await expect(sandbox.stop()).resolves.not.toThrow();
  });

  it('accepts custom securityMode', () => {
    const sandbox = mockSecuredSandbox({}, { securityMode: 'minimal' });
    expect(sandbox.securityMode).toBe('minimal');
  });
});
```

**Step 2: Run tests to verify failure**

```bash
npx vitest run src/testing/testing.test.ts
```

**Step 3: Implement testing/index.ts**

```ts
import type { SecuredSandbox, ExecResult, SecurityMode } from '../core/types.js';

interface MockConfig {
  commands?: Record<string, ExecResult>;
  files?: Record<string, string>;
}

interface MockOptions {
  securityMode?: SecurityMode;
  sessionId?: string;
}

export function mockSecuredSandbox(
  config: MockConfig,
  opts?: MockOptions,
): SecuredSandbox {
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
```

**Step 4: Run tests**

```bash
npx vitest run src/testing/testing.test.ts
```

**Step 5: Commit**

```bash
git add src/testing/
git commit -m "feat: mockSecuredSandbox testing utility"
```

---

### Task 16: Package Exports & Build

**Files:**
- Create: `src/index.ts`
- Modify: verify all existing index.ts files

**Step 1: Write src/index.ts**

```ts
export { secureSandbox, createSandbox } from './api.js';
export type {
  SecuredSandbox,
  SandboxAdapter,
  ExecResult,
  ReadFileResult,
  WriteFileResult,
  SecureConfig,
  CreateSandboxConfig,
  SecurityMode,
  InstallStrategy,
} from './core/types.js';
export type { PolicyDefinition } from './policies/schema.js';
export {
  AgentSHError,
  PolicyValidationError,
  MissingPeerDependencyError,
  IncompatibleProviderVersionError,
  ProvisioningError,
  IntegrityError,
  RuntimeError,
} from './core/errors.js';

// Namespaced re-exports for convenience
import * as policies from './policies/index.js';
import * as adapters from './adapters/index.js';
export { policies, adapters };
```

**Step 2: Typecheck**

```bash
npx tsc --noEmit
```

Fix any type errors across all files.

**Step 3: Build**

```bash
npx tsup
```

Verify output in `dist/`:
- `dist/index.js` and `dist/index.d.ts`
- `dist/adapters/index.js`, `dist/adapters/vercel.js`, etc.
- `dist/policies/index.js`
- `dist/testing/index.js`

**Step 4: Run all tests**

```bash
npx vitest run
```

All tests must pass.

**Step 5: Commit**

```bash
git add src/index.ts
git commit -m "feat: package exports and build configuration"
```

---

### Task 17: Final Verification

**Step 1: Run full test suite**

```bash
npm test
```

**Step 2: Run typecheck**

```bash
npx tsc --noEmit
```

**Step 3: Run build**

```bash
npm run build
```

**Step 4: Verify export paths resolve**

```bash
node -e "import('@agentsh/secure-sandbox').then(m => console.log(Object.keys(m)))"
```

(May need to use the dist path directly for local testing.)

**Step 5: Commit any remaining fixes**

```bash
git add -A
git commit -m "chore: final verification and fixes"
```

---

## Dependency Graph

```
Task 1 (scaffold)
  └→ Task 2 (types + errors)
       ├→ Task 3 (policy schema)
       │    ├→ Task 4 (presets)
       │    ├→ Task 5 (merge)
       │    └→ Task 6 (serialization)
       │         └→ Task 7 (policy exports)
       ├→ Task 8 (integrity)
       ├→ Task 9 (shell escape)
       │    └→ Task 13 (adapters)
       ├→ Task 10 (server config)
       ├→ Task 11 (provisioning) ← depends on 6, 8, 10
       ├→ Task 12 (runtime)
       ├→ Task 14 (main API) ← depends on 11, 12, 13
       ├→ Task 15 (testing utils)
       └→ Task 16 (exports) ← depends on all above
            └→ Task 17 (verification)
```

**Parallelizable groups (for subagent execution):**
- Tasks 3-10 can run in parallel after Task 2 (except 4/5/6 depend on 3, and 7 depends on 6)
- Tasks 11, 12, 13, 15 can run in parallel after their deps
- Tasks 14, 16, 17 are sequential
