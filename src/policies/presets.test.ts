import { describe, it, expect } from 'vitest';
import { agentDefault, devSafe, ciStrict, agentSandbox } from './presets.js';
import { PolicyDefinitionSchema } from './schema.js';

describe('presets', () => {
  describe('agentDefault', () => {
    it('returns a valid PolicyDefinition', () => {
      const policy = agentDefault();
      expect(PolicyDefinitionSchema.safeParse(policy).success).toBe(true);
    });

    it('allows env and printenv (env_policy handles secret filtering)', () => {
      const policy = agentDefault();
      const allowCommands = policy.commands!
        .filter((r): r is { allow: string | string[] } => 'allow' in r)
        .flatMap(r => Array.isArray(r.allow) ? r.allow : [r.allow]);
      expect(allowCommands).toContain('env');
      expect(allowCommands).toContain('printenv');
    });

    it('denies network by default (last rule is deny *)', () => {
      const policy = agentDefault();
      const lastNetRule = policy.network![policy.network!.length - 1];
      expect('deny' in lastNetRule && lastNetRule.deny).toBe('*');
    });

    it('denies files by default (last file rule is deny **)', () => {
      const policy = agentDefault();
      const lastFileRule = policy.file![policy.file!.length - 1];
      expect('deny' in lastFileRule && lastFileRule.deny).toBe('**');
    });

    it('allows workspace read/write/create with extended ops', () => {
      const policy = agentDefault();
      const workspaceAllow = policy.file!.find(
        r => 'allow' in r && (r as any).allow === '/workspace/**',
      ) as any;
      expect(workspaceAllow).toBeDefined();
      expect(workspaceAllow.ops).toContain('read');
      expect(workspaceAllow.ops).toContain('write');
      expect(workspaceAllow.ops).toContain('open');
      expect(workspaceAllow.ops).toContain('stat');
    });

    it('soft-deletes workspace files', () => {
      const policy = agentDefault();
      const softDelete = policy.file!.find(
        r => 'softDelete' in r && (r as any).softDelete === '/workspace/**',
      );
      expect(softDelete).toBeDefined();
    });

    it('allows system paths read-only', () => {
      const policy = agentDefault();
      const systemRead = policy.file!.find(
        r => 'allow' in r && Array.isArray((r as any).allow) && (r as any).allow.includes('/usr/**'),
      ) as any;
      expect(systemRead).toBeDefined();
      expect(systemRead.ops).toContain('read');
      expect(systemRead.ops).not.toContain('write');
    });

    it('allows device files', () => {
      const policy = agentDefault();
      const devRule = policy.file!.find(
        r => 'allow' in r && Array.isArray((r as any).allow) && (r as any).allow.includes('/dev/null'),
      );
      expect(devRule).toBeDefined();
    });

    it('allows /proc/self for introspection', () => {
      const policy = agentDefault();
      const procRule = policy.file!.find(
        r => 'allow' in r && Array.isArray((r as any).allow) && (r as any).allow.includes('/proc/self/**'),
      );
      expect(procRule).toBeDefined();
    });

    it('denies dangerous binaries', () => {
      const policy = agentDefault();
      const firstRule = policy.file![0];
      expect('deny' in firstRule).toBe(true);
      const denyPaths = Array.isArray((firstRule as any).deny) ? (firstRule as any).deny : [(firstRule as any).deny];
      expect(denyPaths).toContain('/usr/bin/sudo');
      expect(denyPaths).toContain('/usr/bin/su');
    });

    it('allows curl and wget (no redirect)', () => {
      const policy = agentDefault();
      const allowCommands = policy.commands!
        .filter((r): r is { allow: string | string[] } => 'allow' in r)
        .flatMap(r => Array.isArray(r.allow) ? r.allow : [r.allow]);
      expect(allowCommands).toContain('curl');
      expect(allowCommands).toContain('wget');
      const redirectRules = policy.commands!.filter(r => 'redirect' in r);
      expect(redirectRules.length).toBe(0);
    });

    it('has allow-all command catch-all (security via file + network rules)', () => {
      const policy = agentDefault();
      const lastCmdRule = policy.commands![policy.commands!.length - 1];
      expect('allow' in lastCmdRule && lastCmdRule.allow).toBe('*');
    });

    it('has CIDR rules for localhost', () => {
      const policy = agentDefault();
      const cidrRule = policy.network!.find(
        r => 'allowCidrs' in r,
      ) as any;
      expect(cidrRule).toBeDefined();
      expect(cidrRule.allowCidrs).toContain('127.0.0.1/32');
      expect(cidrRule.allowCidrs).toContain('::1/128');
    });

    it('blocks metadata services via denyCidrs', () => {
      const policy = agentDefault();
      const metadataDeny = policy.network!.find(
        r => 'denyCidrs' in r && (r as any).denyCidrs.includes('169.254.169.254/32'),
      );
      expect(metadataDeny).toBeDefined();
    });

    it('blocks private networks via denyCidrs', () => {
      const policy = agentDefault();
      const privateDeny = policy.network!.find(
        r => 'denyCidrs' in r && (r as any).denyCidrs.includes('10.0.0.0/8'),
      );
      expect(privateDeny).toBeDefined();
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

      it('approves new packages (package_too_new)', () => {
        const policy = agentDefault();
        const rule = policy.packageRules!.find(
          r => r.match.reasons?.includes('package_too_new'),
        );
        expect(rule).toBeDefined();
        expect(rule!.action).toBe('approve');
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
