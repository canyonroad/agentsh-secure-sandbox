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
});
