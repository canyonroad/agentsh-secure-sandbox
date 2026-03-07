import type { PolicyDefinition } from './schema.js';
import { validatePolicy } from './schema.js';

const CATEGORIES = ['file', 'network', 'commands', 'env', 'dns', 'connect'] as const;

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
    for (const key of CATEGORIES) {
      if (override[key] != null) {
        const baseRules = result[key] ?? [];
        result[key] = mode === 'append'
          ? [...baseRules, ...override[key]!]
          : [...override[key]!, ...baseRules];
      }
    }
  }
  return result;
}
