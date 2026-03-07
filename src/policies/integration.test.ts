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
    expect(parsed.file_rules.length).toBeGreaterThanOrEqual(4);
    const stripeRule = parsed.network_rules.find(
      (r: any) => r.decision === 'allow' && r.domains?.includes('api.stripe.com'),
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

  it('merge appends after base', () => {
    const policy = merge(
      { network: [{ deny: '*' }] },
      { network: [{ allow: ['extra.com'] }] },
    );
    const yamlStr = serializePolicy(policy);
    const parsed = yaml.load(yamlStr) as any;
    expect(parsed.network_rules[0].decision).toBe('deny');
    expect(parsed.network_rules[1].decision).toBe('allow');
  });
});
