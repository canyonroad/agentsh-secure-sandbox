# Package Install Checks — Design

## Context

agentsh intercepts package install commands (npm, pip, yarn, pnpm, uv, poetry) and checks packages against security providers before allowing installation. This is configured via `package_checks` in the server config and `package_rules` in the policy. secure-sandbox needs to expose this through its JS API.

## API Surface

### SecureConfig (server config side)

```ts
packageChecks?: false | PackageChecksConfig;
```

Disabled by default. Enable with `packageChecks: {}` to get free providers (osv, depsdev, local). Pass `false` to explicitly disable (same as omitting).

```ts
interface PackageChecksConfig {
  scope?: 'new_packages_only' | 'all_installs';
  providers?: {
    osv?: boolean | ProviderConfig;
    depsdev?: boolean | ProviderConfig;
    local?: boolean | ProviderConfig;
    socket?: boolean | ProviderConfig;
    snyk?: boolean | ProviderConfig;
    [name: string]: boolean | ProviderConfig | undefined;
  };
}

interface ProviderConfig {
  enabled?: boolean;
  priority?: number;
  timeout?: string;
  onFailure?: 'warn' | 'deny' | 'allow' | 'approve';
  apiKeyEnv?: string;
  type?: 'exec';
  command?: string;
  options?: Record<string, unknown>;
}
```

### PolicyDefinition (policy side)

```ts
packageRules?: PackageRule[];

interface PackageRule {
  match: PackageMatch;
  action: 'allow' | 'warn' | 'approve' | 'block';
  reason?: string;
}

interface PackageMatch {
  packages?: string[];
  namePatterns?: string[];
  findingType?: string;
  severity?: string;
  reasons?: string[];
  licenseSpdx?: { allow?: string[]; deny?: string[] };
  ecosystem?: string;
  options?: Record<string, unknown>;
}
```

## Defaults

- `packageChecks` is **disabled by default** (unlike threatFeeds) because it requires provider configuration and network calls
- When enabled, three free providers are active: osv (priority 1), depsdev (priority 2), local (priority 0)
- `agentDefault()` preset includes package rules that act on findings:
  - Block: critical vulns, malware, typosquats, AGPL/SSPL licenses
  - Warn: medium vulns
  - Approve: packages < 30 days old

## Serialization

`generateServerConfig()` maps JS config to agentsh YAML:
- `packageChecks: {}` → `package_checks: { enabled: true }` + default providers
- `providers: { socket: true }` → enables with defaults
- `providers: { socket: { apiKeyEnv: 'KEY' } }` → enables with overrides
- `providers: { osv: false }` → disables a default provider
- Unmentioned default providers stay enabled
- camelCase keys → snake_case in YAML

`serializePolicy()` maps `packageRules` → `package_rules` YAML.

## Not included (deferred)

- **Registry trust configuration** — safe defaults (public = check_full, unknown = check_local_only)
- **Resolver configuration** — built-in defaults are correct
- **Cache configuration** — agentsh defaults are sensible
- **Watchtower** — not yet implemented in agentsh

## Files to change

| File | Change |
|------|--------|
| `src/core/types.ts` | Add types, add `packageChecks` to `SecureConfig` |
| `src/core/config.ts` | Serialize `packageChecks` → `package_checks` YAML |
| `src/core/provision.ts` | Pass `packageChecks` to `generateServerConfig()` |
| `src/policies/schema.ts` | Add `packageRules` to Zod schema |
| `src/policies/serialize.ts` | Serialize `packageRules` → `package_rules` YAML |
| `src/policies/presets.ts` | Add default package rules to `agentDefault()` |
| `src/core/config.test.ts` | Tests for YAML generation |
| `src/policies/schema.test.ts` | Tests for validation |
| `src/policies/serialize.test.ts` | Tests for serialization |
| `src/policies/presets.test.ts` | Test preset includes package rules |
| `docs/api.md` | Document new config options |

## Verification

1. `npm run build && npm run typecheck` — no type errors
2. `npx vitest run` — all tests pass
3. Manual: generate config YAML and compare against agentsh's expected format
