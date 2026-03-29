import type { PolicyDefinition } from './schema.js';
import { validatePolicy } from './schema.js';

/** Categories whose values are arrays (first-match-wins rule lists). */
const ARRAY_CATEGORIES = ['file', 'network', 'commands', 'env', 'dns', 'connect', 'packageRules', 'signalRules', 'unixSocketRules'] as const;

/** Categories whose values are plain objects (last-write-wins merge). */
const OBJECT_CATEGORIES = ['envPolicy', 'resourceLimits', 'auditSettings'] as const;

/**
 * Merge policy overrides AFTER base rules for each category.
 * Since agentsh evaluates first-match-wins, appended rules only apply
 * to paths not already matched by base.
 */
export function merge(base: PolicyDefinition, ...overrides: Partial<PolicyDefinition>[]): PolicyDefinition {
  return validatePolicy(mergeInternal(base, overrides, 'append'));
}

/**
 * Merge policy overrides BEFORE base rules for each category,
 * making overrides take priority in first-match-wins evaluation.
 */
export function mergePrepend(base: PolicyDefinition, ...overrides: Partial<PolicyDefinition>[]): PolicyDefinition {
  return validatePolicy(mergeInternal(base, overrides, 'prepend'));
}

function mergeInternal(
  base: PolicyDefinition,
  overrides: Partial<PolicyDefinition>[],
  mode: 'append' | 'prepend',
): PolicyDefinition {
  const result: any = { ...base };
  for (const override of overrides) {
    // Array categories: concatenate in order
    for (const key of ARRAY_CATEGORIES) {
      if (override[key] != null) {
        const baseRules = result[key] ?? [];
        result[key] = mode === 'append'
          ? [...baseRules, ...override[key]!]
          : [...override[key]!, ...baseRules];
      }
    }
    // Object categories: shallow merge (override wins)
    for (const key of OBJECT_CATEGORIES) {
      if (override[key] != null) {
        result[key] = { ...(result[key] ?? {}), ...override[key] };
      }
    }
  }
  return result;
}
