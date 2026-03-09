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

    it('denies network by default (last rule is deny *)', () => {
      const policy = agentDefault();
      const lastNetRule = policy.network![policy.network!.length - 1];
      expect('deny' in lastNetRule && lastNetRule.deny).toBe('*');
    });

    it('allows workspace read/write/create', () => {
      const policy = agentDefault();
      const firstFileRule = policy.file![0];
      expect('allow' in firstFileRule && firstFileRule.allow).toBe('/workspace/**');
    });

    it('redirects curl and wget', () => {
      const policy = agentDefault();
      const redirectRules = policy.commands!.filter(r => 'redirect' in r);
      expect(redirectRules.length).toBeGreaterThan(0);
    });

    it('denies cloud credential paths', () => {
      const policy = agentDefault();
      const denyPaths = policy.file!
        .filter((r): r is { deny: string | string[] } => 'deny' in r)
        .flatMap(r => Array.isArray(r.deny) ? r.deny : [r.deny]);
      expect(denyPaths).toContain('~/.aws/**');
      expect(denyPaths).toContain('~/.gcp/**');
      expect(denyPaths).toContain('~/.azure/**');
      expect(denyPaths).toContain('~/.config/gcloud/**');
    });

    it('denies shell config files', () => {
      const policy = agentDefault();
      const denyPaths = policy.file!
        .filter((r): r is { deny: string | string[] } => 'deny' in r)
        .flatMap(r => Array.isArray(r.deny) ? r.deny : [r.deny]);
      expect(denyPaths).toContain('~/.bashrc');
      expect(denyPaths).toContain('~/.zshrc');
    });

    it('denies writes to agent config files but allows reads', () => {
      const policy = agentDefault();
      const agentConfigRule = policy.file!.find(
        (r): r is { deny: string[]; ops: string[] } =>
          'deny' in r && Array.isArray((r as any).deny) && (r as any).deny.includes('**/.cursorrules'),
      ) as any;
      expect(agentConfigRule).toBeDefined();
      expect(agentConfigRule.deny).toContain('**/.cursorrules');
      expect(agentConfigRule.deny).toContain('**/CLAUDE.md');
      expect(agentConfigRule.deny).toContain('**/copilot-instructions.md');
      expect(agentConfigRule.ops).toContain('write');
      expect(agentConfigRule.ops).toContain('create');
      expect(agentConfigRule.ops).toContain('delete');
      expect(agentConfigRule.ops).not.toContain('read');
    });

    it('allows Go, Rust, and GitHub domains', () => {
      const policy = agentDefault();
      const allowDomains = policy.network!
        .filter((r): r is { allow: string | string[]; ports?: number[] } => 'allow' in r)
        .flatMap(r => Array.isArray(r.allow) ? r.allow : [r.allow]);
      expect(allowDomains).toContain('crates.io');
      expect(allowDomains).toContain('proxy.golang.org');
      expect(allowDomains).toContain('github.com');
    });

    it('accepts extensions and appends them', () => {
      const policy = agentDefault({
        network: [{ allow: ['api.stripe.com'], ports: [443] }],
      });
      expect(PolicyDefinitionSchema.safeParse(policy).success).toBe(true);
      // Extension appended — last network rule should be the extension (since base deny * is before)
      // Actually extensions are appended AFTER base, so deny * stays, and extension is after
      const networkRules = policy.network!;
      expect(networkRules.length).toBeGreaterThan(2);
      const hasStripe = networkRules.some(r => 'allow' in r && (Array.isArray(r.allow) ? r.allow.includes('api.stripe.com') : r.allow === 'api.stripe.com'));
      expect(hasStripe).toBe(true);
    });

    it('does not modify base when extensions are given', () => {
      const base1 = agentDefault();
      const extended = agentDefault({ network: [{ allow: ['extra.com'] }] });
      const base2 = agentDefault();
      expect(base1.network!.length).toBe(base2.network!.length);
    });

    describe('packageRules', () => {
      it('includes packageRules', () => {
        const policy = agentDefault();
        expect(policy.packageRules).toBeDefined();
        expect(Array.isArray(policy.packageRules)).toBe(true);
      });

      it('has expected number of rules', () => {
        const policy = agentDefault();
        expect(policy.packageRules!.length).toBe(6);
      });

      it('blocks critical vulnerabilities', () => {
        const policy = agentDefault();
        const rule = policy.packageRules!.find(
          r => r.match.findingType === 'vulnerability' && r.match.severity === 'critical',
        );
        expect(rule).toBeDefined();
        expect(rule!.action).toBe('block');
      });

      it('blocks known malware', () => {
        const policy = agentDefault();
        const rule = policy.packageRules!.find(
          r => r.match.findingType === 'malware',
        );
        expect(rule).toBeDefined();
        expect(rule!.action).toBe('block');
      });

      it('blocks typosquats', () => {
        const policy = agentDefault();
        const rule = policy.packageRules!.find(
          r => r.match.findingType === 'reputation' && r.match.reasons?.includes('typosquat'),
        );
        expect(rule).toBeDefined();
        expect(rule!.action).toBe('block');
      });

      it('warns on medium vulnerabilities', () => {
        const policy = agentDefault();
        const rule = policy.packageRules!.find(
          r => r.match.findingType === 'vulnerability' && r.match.severity === 'medium',
        );
        expect(rule).toBeDefined();
        expect(rule!.action).toBe('warn');
      });

      it('blocks copyleft licenses (AGPL-3.0-only, SSPL-1.0)', () => {
        const policy = agentDefault();
        const rule = policy.packageRules!.find(
          r => r.match.findingType === 'license',
        );
        expect(rule).toBeDefined();
        expect(rule!.action).toBe('block');
        expect(rule!.match.licenseSpdx?.deny).toEqual(['AGPL-3.0-only', 'SSPL-1.0']);
      });

      it('approves packages newer than 30 days (package_too_new)', () => {
        const policy = agentDefault();
        const rule = policy.packageRules!.find(
          r => r.match.reasons?.includes('package_too_new'),
        );
        expect(rule).toBeDefined();
        expect(rule!.action).toBe('approve');
        expect(rule!.match.options).toEqual({ maxAgeDays: 30 });
      });

      it('validates against PolicyDefinitionSchema with packageRules', () => {
        const policy = agentDefault();
        expect(PolicyDefinitionSchema.safeParse(policy).success).toBe(true);
      });
    });
  });

  describe('devSafe', () => {
    it('returns a valid PolicyDefinition', () => {
      expect(PolicyDefinitionSchema.safeParse(devSafe()).success).toBe(true);
    });

    it('does not deny all network', () => {
      const policy = devSafe();
      const hasDenyAll = policy.network!.some(r => 'deny' in r && r.deny === '*');
      expect(hasDenyAll).toBe(false);
    });

    it('allows workspace', () => {
      const policy = devSafe();
      const firstFileRule = policy.file![0];
      expect('allow' in firstFileRule).toBe(true);
    });

    it('denies cloud credential paths', () => {
      const policy = devSafe();
      const denyPaths = policy.file!
        .filter((r): r is { deny: string | string[] } => 'deny' in r)
        .flatMap(r => Array.isArray(r.deny) ? r.deny : [r.deny]);
      expect(denyPaths).toContain('~/.aws/**');
      expect(denyPaths).toContain('~/.azure/**');
    });

    it('denies shell config files', () => {
      const policy = devSafe();
      const denyPaths = policy.file!
        .filter((r): r is { deny: string | string[] } => 'deny' in r)
        .flatMap(r => Array.isArray(r.deny) ? r.deny : [r.deny]);
      expect(denyPaths).toContain('~/.bashrc');
      expect(denyPaths).toContain('~/.zshrc');
    });

    it('accepts extensions', () => {
      const policy = devSafe({ commands: [{ deny: ['rm'] }] });
      expect(PolicyDefinitionSchema.safeParse(policy).success).toBe(true);
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

    it('denies all network except registries', () => {
      const policy = ciStrict();
      const hasDenyAll = policy.network!.some(r => 'deny' in r && r.deny === '*');
      expect(hasDenyAll).toBe(true);
    });

    it('denies cloud credential paths before the catch-all deny', () => {
      const policy = ciStrict();
      const denyPaths = policy.file!
        .filter((r): r is { deny: string | string[] } => 'deny' in r)
        .flatMap(r => Array.isArray(r.deny) ? r.deny : [r.deny]);
      expect(denyPaths).toContain('~/.aws/**');
    });

    it('allows Go and Rust registries', () => {
      const policy = ciStrict();
      const allowDomains = policy.network!
        .filter((r): r is { allow: string | string[]; ports?: number[] } => 'allow' in r)
        .flatMap(r => Array.isArray(r.allow) ? r.allow : [r.allow]);
      expect(allowDomains).toContain('crates.io');
      expect(allowDomains).toContain('proxy.golang.org');
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

    it('denies all network', () => {
      const policy = agentSandbox();
      const hasDenyAll = policy.network!.some(r => 'deny' in r && r.deny === '*');
      expect(hasDenyAll).toBe(true);
    });
  });
});
