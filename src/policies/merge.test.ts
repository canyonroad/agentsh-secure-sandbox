import { describe, it, expect } from 'vitest';
import { merge, mergePrepend } from './merge.js';
import { PolicyValidationError } from '../core/errors.js';
import type { PolicyDefinition } from './schema.js';

describe('merge', () => {
  it('appends extension rules after base', () => {
    const base: PolicyDefinition = {
      file: [{ allow: '/workspace/**' }],
      network: [{ deny: '*' }],
    };
    const extension: Partial<PolicyDefinition> = {
      file: [{ deny: '/workspace/.secret' }],
    };

    const result = merge(base, extension);

    expect(result.file).toHaveLength(2);
    expect(result.file![0]).toEqual({ allow: '/workspace/**' });
    expect(result.file![1]).toEqual({ deny: '/workspace/.secret' });
  });

  it('preserves categories not in extensions', () => {
    const base: PolicyDefinition = {
      file: [{ allow: '/workspace/**' }],
      network: [{ deny: '*' }],
      commands: [{ deny: ['env'] }],
    };
    const extension: Partial<PolicyDefinition> = {
      file: [{ deny: '/tmp/**' }],
    };

    const result = merge(base, extension);

    expect(result.network).toEqual([{ deny: '*' }]);
    expect(result.commands).toEqual([{ deny: ['env'] }]);
    expect(result.file).toHaveLength(2);
  });

  it('handles multiple overrides', () => {
    const base: PolicyDefinition = {
      file: [{ allow: '/workspace/**' }],
    };
    const ext1: Partial<PolicyDefinition> = {
      file: [{ deny: '/workspace/.env' }],
    };
    const ext2: Partial<PolicyDefinition> = {
      file: [{ deny: '/workspace/.secret' }],
      network: [{ deny: '*' }],
    };

    const result = merge(base, ext1, ext2);

    expect(result.file).toHaveLength(3);
    expect(result.file![0]).toEqual({ allow: '/workspace/**' });
    expect(result.file![1]).toEqual({ deny: '/workspace/.env' });
    expect(result.file![2]).toEqual({ deny: '/workspace/.secret' });
    expect(result.network).toEqual([{ deny: '*' }]);
  });

  it('validates the merged result and throws on invalid', () => {
    const base: PolicyDefinition = {
      file: [{ allow: '/workspace/**' }],
    };
    const invalid = { file: [{ invalid: true }] } as any;

    expect(() => merge(base, invalid)).toThrow(PolicyValidationError);
  });

  it('returns a valid policy when merging empty overrides', () => {
    const base: PolicyDefinition = {
      file: [{ allow: '/workspace/**' }],
    };
    const result = merge(base, {});
    expect(result).toEqual(base);
  });

  it('does not mutate the base policy', () => {
    const base: PolicyDefinition = {
      file: [{ allow: '/workspace/**' }],
    };
    const baseCopy = JSON.parse(JSON.stringify(base));

    merge(base, { file: [{ deny: '/tmp/**' }] });

    expect(base).toEqual(baseCopy);
  });

  it('preserves base rules when override category is null', () => {
    const base: PolicyDefinition = {
      file: [{ allow: '/workspace/**' }],
    };
    const result = merge(base, { file: null as any });
    expect(result.file).toEqual([{ allow: '/workspace/**' }]);
  });

  it('handles empty array override (no rules appended)', () => {
    const base: PolicyDefinition = {
      file: [{ allow: '/workspace/**' }],
      network: [{ deny: '*' }],
    };
    const result = merge(base, { file: [] });
    expect(result.file).toEqual([{ allow: '/workspace/**' }]);
    expect(result.network).toEqual([{ deny: '*' }]);
  });
});

describe('mergePrepend', () => {
  it('prepends extension rules before base', () => {
    const base: PolicyDefinition = {
      file: [{ allow: '/workspace/**' }],
      network: [{ deny: '*' }],
    };
    const extension: Partial<PolicyDefinition> = {
      file: [{ deny: '/workspace/.secret' }],
    };

    const result = mergePrepend(base, extension);

    expect(result.file).toHaveLength(2);
    expect(result.file![0]).toEqual({ deny: '/workspace/.secret' });
    expect(result.file![1]).toEqual({ allow: '/workspace/**' });
  });

  it('preserves categories not in extensions', () => {
    const base: PolicyDefinition = {
      file: [{ allow: '/workspace/**' }],
      network: [{ deny: '*' }],
    };
    const extension: Partial<PolicyDefinition> = {
      file: [{ deny: '/tmp/**' }],
    };

    const result = mergePrepend(base, extension);

    expect(result.network).toEqual([{ deny: '*' }]);
  });

  it('handles multiple overrides in correct order', () => {
    const base: PolicyDefinition = {
      file: [{ allow: '/workspace/**' }],
    };
    const ext1: Partial<PolicyDefinition> = {
      file: [{ deny: '/workspace/.env' }],
    };
    const ext2: Partial<PolicyDefinition> = {
      file: [{ deny: '/workspace/.secret' }],
    };

    const result = mergePrepend(base, ext1, ext2);

    // ext1 prepended first, then ext2 prepended before everything
    expect(result.file).toHaveLength(3);
    expect(result.file![0]).toEqual({ deny: '/workspace/.secret' });
    expect(result.file![1]).toEqual({ deny: '/workspace/.env' });
    expect(result.file![2]).toEqual({ allow: '/workspace/**' });
  });

  it('validates the merged result and throws on invalid', () => {
    const base: PolicyDefinition = {
      file: [{ allow: '/workspace/**' }],
    };
    const invalid = { file: [{ invalid: true }] } as any;

    expect(() => mergePrepend(base, invalid)).toThrow(PolicyValidationError);
  });

  it('appends packageRules from extensions', () => {
    const base: PolicyDefinition = {
      packageRules: [
        { match: { findingType: 'malware' }, action: 'block' },
      ],
    };
    const extension: Partial<PolicyDefinition> = {
      packageRules: [
        { match: { findingType: 'vulnerability', severity: 'high' }, action: 'warn' },
      ],
    };

    const result = merge(base, extension);

    expect(result.packageRules).toHaveLength(2);
    expect(result.packageRules![0].match.findingType).toBe('malware');
    expect(result.packageRules![1].match.findingType).toBe('vulnerability');
  });

  it('prepends packageRules from extensions', () => {
    const base: PolicyDefinition = {
      packageRules: [
        { match: { findingType: 'malware' }, action: 'block' },
      ],
    };
    const extension: Partial<PolicyDefinition> = {
      packageRules: [
        { match: { findingType: 'vulnerability', severity: 'high' }, action: 'warn' },
      ],
    };

    const result = mergePrepend(base, extension);

    expect(result.packageRules).toHaveLength(2);
    expect(result.packageRules![0].match.findingType).toBe('vulnerability');
    expect(result.packageRules![1].match.findingType).toBe('malware');
  });
});

describe('merge — object categories', () => {
  it('shallow-merges envPolicy (override wins)', () => {
    const base: PolicyDefinition = {
      envPolicy: { deny: ['*_SECRET*'], blockIteration: true },
    };
    const extension: Partial<PolicyDefinition> = {
      envPolicy: { deny: ['*_PASSWORD*'], maxBytes: 2048 },
    };

    const result = merge(base, extension);

    expect(result.envPolicy!.deny).toEqual(['*_PASSWORD*']);
    expect(result.envPolicy!.maxBytes).toBe(2048);
    expect(result.envPolicy!.blockIteration).toBe(true);
  });

  it('shallow-merges resourceLimits (override wins)', () => {
    const base: PolicyDefinition = {
      resourceLimits: { maxMemoryMb: 8192, pidsMax: 500, commandTimeout: '15m' },
    };
    const extension: Partial<PolicyDefinition> = {
      resourceLimits: { maxMemoryMb: 4096, idleTimeout: '10m' },
    };

    const result = merge(base, extension);

    expect(result.resourceLimits!.maxMemoryMb).toBe(4096);
    expect(result.resourceLimits!.pidsMax).toBe(500);
    expect(result.resourceLimits!.commandTimeout).toBe('15m');
    expect(result.resourceLimits!.idleTimeout).toBe('10m');
  });

  it('shallow-merges auditSettings (override wins)', () => {
    const base: PolicyDefinition = {
      auditSettings: { logAllowed: false, logDenied: true },
    };
    const extension: Partial<PolicyDefinition> = {
      auditSettings: { logAllowed: true, includeStderr: true },
    };

    const result = merge(base, extension);

    expect(result.auditSettings!.logAllowed).toBe(true);
    expect(result.auditSettings!.logDenied).toBe(true);
    expect(result.auditSettings!.includeStderr).toBe(true);
  });

  it('adds object category when base has none', () => {
    const base: PolicyDefinition = {
      file: [{ allow: '/workspace/**' }],
    };
    const extension: Partial<PolicyDefinition> = {
      envPolicy: { deny: ['SECRET'], blockIteration: true },
    };

    const result = merge(base, extension);

    expect(result.envPolicy).toEqual({ deny: ['SECRET'], blockIteration: true });
  });

  it('preserves object category when override has none', () => {
    const base: PolicyDefinition = {
      resourceLimits: { maxMemoryMb: 8192 },
    };

    const result = merge(base, {});

    expect(result.resourceLimits).toEqual({ maxMemoryMb: 8192 });
  });

  it('appends signalRules as array category', () => {
    const base: PolicyDefinition = {
      signalRules: [
        { name: 'allow-self', signals: ['@all'], target: { type: 'self' }, decision: 'allow' },
      ],
    };
    const extension: Partial<PolicyDefinition> = {
      signalRules: [
        { name: 'deny-ext', signals: ['@fatal'], target: { type: 'external' }, decision: 'deny' },
      ],
    };

    const result = merge(base, extension);

    expect(result.signalRules).toHaveLength(2);
    expect(result.signalRules![0].name).toBe('allow-self');
    expect(result.signalRules![1].name).toBe('deny-ext');
  });

  it('prepends unixSocketRules as array category', () => {
    const base: PolicyDefinition = {
      unixSocketRules: [
        { name: 'deny-all', paths: ['/var/run/**'], decision: 'deny' },
      ],
    };
    const extension: Partial<PolicyDefinition> = {
      unixSocketRules: [
        { name: 'allow-docker', paths: ['/var/run/docker.sock'], decision: 'allow' },
      ],
    };

    const result = mergePrepend(base, extension);

    expect(result.unixSocketRules).toHaveLength(2);
    expect(result.unixSocketRules![0].name).toBe('allow-docker');
    expect(result.unixSocketRules![1].name).toBe('deny-all');
  });
});
