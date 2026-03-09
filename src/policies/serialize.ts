import yaml from 'js-yaml';
import type {
  PolicyDefinition,
  FileRule,
  NetworkRule,
  CommandRule,
  EnvRule,
  DnsRedirect,
  ConnectRedirect,
  PackageRule,
} from './schema.js';

// ─── Helpers ────────────────────────────────────────────────

/** Normalize a string-or-array value to always be an array. */
function toArray(value: string | string[]): string[] {
  return Array.isArray(value) ? value : [value];
}

/** Detect the decision key from a rule object. */
type DecisionKey = 'allow' | 'deny' | 'redirect' | 'audit' | 'softDelete';

const FILE_DECISION_KEYS: DecisionKey[] = [
  'allow',
  'deny',
  'redirect',
  'audit',
  'softDelete',
];

const SIMPLE_DECISION_KEYS: DecisionKey[] = ['allow', 'deny', 'redirect'];

function findDecision(
  rule: Record<string, unknown>,
  keys: DecisionKey[],
): { key: DecisionKey; value: unknown } {
  for (const k of keys) {
    if (k in rule) {
      return { key: k, value: rule[k] };
    }
  }
  throw new Error(`No decision key found in rule: ${JSON.stringify(rule)}`);
}

/** Map softDelete → soft_delete for YAML output. */
function yamlDecision(key: DecisionKey): string {
  return key === 'softDelete' ? 'soft_delete' : key;
}

// ─── File rules ─────────────────────────────────────────────

function serializeFileRules(rules: FileRule[]): Record<string, unknown>[] {
  return rules.map((rule, i) => {
    const r = rule as Record<string, unknown>;
    const { key, value } = findDecision(r, FILE_DECISION_KEYS);
    const paths = toArray(value as string | string[]);

    const out: Record<string, unknown> = {
      name: `file-rule-${i}`,
      paths,
    };

    if ('ops' in r && r.ops) {
      out.operations = r.ops;
    }

    out.decision = yamlDecision(key);

    if (key === 'redirect' && 'to' in r) {
      out.redirect_to = r.to;
    }

    return out;
  });
}

// ─── Network rules ──────────────────────────────────────────

function serializeNetworkRules(
  rules: NetworkRule[],
): Record<string, unknown>[] {
  return rules.map((rule, i) => {
    const r = rule as Record<string, unknown>;
    const { key, value } = findDecision(r, SIMPLE_DECISION_KEYS);
    const domains = toArray(value as string | string[]);

    const out: Record<string, unknown> = {
      name: `network-rule-${i}`,
      domains,
      decision: key,
    };

    if ('ports' in r && r.ports) {
      out.ports = r.ports;
    }

    if (key === 'redirect' && 'to' in r) {
      out.redirect_to = r.to;
    }

    return out;
  });
}

// ─── Command rules ──────────────────────────────────────────

function serializeCommandRules(
  rules: CommandRule[],
): Record<string, unknown>[] {
  return rules.map((rule, i) => {
    const r = rule as Record<string, unknown>;
    const { key, value } = findDecision(r, SIMPLE_DECISION_KEYS);
    const commands = toArray(value as string | string[]);

    const out: Record<string, unknown> = {
      name: `command-rule-${i}`,
      commands,
      decision: key,
    };

    if (key === 'redirect' && 'to' in r) {
      const to = r.to;
      if (typeof to === 'string') {
        out.redirect_to = to;
      } else if (typeof to === 'object' && to !== null) {
        const target = to as { cmd: string; args: string[] };
        out.redirect_to = { command: target.cmd, args: target.args };
      }
    }

    return out;
  });
}

// ─── Env rules ──────────────────────────────────────────────

function serializeEnvRules(rules: EnvRule[]): Record<string, unknown>[] {
  return rules.map((rule, i) => {
    const out: Record<string, unknown> = {
      name: `env-rule-${i}`,
      commands: rule.commands,
    };
    if (rule.allow) {
      out.allow = rule.allow;
    }
    if (rule.deny) {
      out.deny = rule.deny;
    }
    return out;
  });
}

// ─── DNS redirects ──────────────────────────────────────────

function serializeDnsRedirects(
  redirects: DnsRedirect[],
): Record<string, unknown>[] {
  return redirects.map((r) => ({
    match: r.match,
    resolve_to: r.resolveTo,
  }));
}

// ─── Connect redirects ──────────────────────────────────────

function serializeConnectRedirects(
  redirects: ConnectRedirect[],
): Record<string, unknown>[] {
  return redirects.map((r) => ({
    match: r.match,
    redirect_to: r.redirectTo,
  }));
}

// ─── Package rules ───────────────────────────────────────────

function serializePackageRules(
  rules: PackageRule[],
): Record<string, unknown>[] {
  return rules.map((rule) => {
    const match: Record<string, unknown> = {};

    if (rule.match.packages) {
      match.packages = rule.match.packages;
    }
    if (rule.match.namePatterns) {
      match.name_patterns = rule.match.namePatterns;
    }
    if (rule.match.findingType) {
      match.finding_type = rule.match.findingType;
    }
    if (rule.match.severity !== undefined) {
      match.severity = rule.match.severity;
    }
    if (rule.match.reasons) {
      match.reasons = rule.match.reasons;
    }
    if (rule.match.licenseSpdx) {
      match.license_spdx = rule.match.licenseSpdx;
    }
    if (rule.match.ecosystem) {
      match.ecosystem = rule.match.ecosystem;
    }
    if (rule.match.options) {
      match.options = rule.match.options;
    }

    const out: Record<string, unknown> = {
      match,
      action: rule.action,
    };

    if (rule.reason) {
      out.reason = rule.reason;
    }

    return out;
  });
}

// ─── Public API ─────────────────────────────────────────────

/**
 * Converts a PolicyDefinition to agentsh YAML format.
 *
 * Omits empty categories from output.
 */
export function serializePolicy(policy: PolicyDefinition): string {
  const doc: Record<string, unknown> = {
    version: 1,
    name: 'secure-sandbox-policy',
  };

  if (policy.file && policy.file.length > 0) {
    doc.file_rules = serializeFileRules(policy.file);
  }

  if (policy.network && policy.network.length > 0) {
    doc.network_rules = serializeNetworkRules(policy.network);
  }

  if (policy.commands && policy.commands.length > 0) {
    doc.command_rules = serializeCommandRules(policy.commands);
  }

  if (policy.env && policy.env.length > 0) {
    doc.env_rules = serializeEnvRules(policy.env);
  }

  if (policy.dns && policy.dns.length > 0) {
    doc.dns_redirects = serializeDnsRedirects(policy.dns);
  }

  if (policy.connect && policy.connect.length > 0) {
    doc.connect_redirects = serializeConnectRedirects(policy.connect);
  }

  if (policy.packageRules && policy.packageRules.length > 0) {
    doc.package_rules = serializePackageRules(policy.packageRules);
  }

  return yaml.dump(doc, { lineWidth: -1 });
}

/**
 * Returns the fixed system policy YAML from the spec (Section 9.4).
 *
 * This static set of rules protects agentsh's own configuration, binaries,
 * and processes from tampering by the agent. These rules are written to a
 * separate system policy directory evaluated before user policy.
 */
export function systemPolicyYaml(): string {
  const doc = {
    version: 1,
    name: '_system-protection',
    file_rules: [
      {
        name: '_system-protect-config',
        paths: ['/etc/agentsh/**'],
        operations: ['write', 'create', 'delete'],
        decision: 'deny',
        message: 'Policy files are immutable during agent execution',
      },
      {
        name: '_system-protect-binary',
        paths: ['/usr/local/bin/agentsh*', '/usr/bin/agentsh*'],
        operations: ['write', 'create', 'delete'],
        decision: 'deny',
        message: 'agentsh binary is immutable during agent execution',
      },
      {
        name: '_system-protect-shim-files',
        paths: ['/usr/bin/agentsh-shell-shim', '/bin/bash', '/bin/sh'],
        operations: ['write', 'create', 'delete'],
        decision: 'deny',
        message: 'Shell and shim binaries are immutable during agent execution',
      },
    ],
    command_rules: [
      {
        name: '_system-protect-process',
        commands: ['kill', 'killall', 'pkill'],
        args_match: ['agentsh'],
        decision: 'deny',
        message: 'Cannot terminate agentsh processes',
      },
    ],
  };

  return yaml.dump(doc, { lineWidth: -1 });
}
