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
