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
  EnvPolicy,
  SignalRule,
  UnixSocketRule,
  ResourceLimits,
  AuditSettings,
  SecretProvider,
  VaultAuth,
  HttpService,
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

    // CIDR-based rules
    if ('allowCidrs' in r) {
      const out: Record<string, unknown> = {
        name: `network-rule-${i}`,
        cidrs: r.allowCidrs,
        decision: 'allow',
      };
      if ('ports' in r && r.ports) out.ports = r.ports;
      return out;
    }
    if ('denyCidrs' in r) {
      return {
        name: `network-rule-${i}`,
        cidrs: r.denyCidrs,
        decision: 'deny',
      };
    }

    // Domain-based rules
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

// ─── Env policy (top-level) ─────────────────────────────────

function serializeEnvPolicy(policy: EnvPolicy): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  if (policy.allow) out.allow = policy.allow;
  if (policy.deny) out.deny = policy.deny;
  if (policy.maxBytes !== undefined) out.max_bytes = policy.maxBytes;
  if (policy.maxKeys !== undefined) out.max_keys = policy.maxKeys;
  if (policy.blockIteration !== undefined) out.block_iteration = policy.blockIteration;
  return out;
}

// ─── Signal rules ──────────────────────────────────────────

function serializeSignalRules(rules: SignalRule[]): Record<string, unknown>[] {
  return rules.map((rule) => {
    const out: Record<string, unknown> = {
      name: rule.name,
      signals: rule.signals,
      target: { type: rule.target.type },
      decision: rule.decision,
    };
    if (rule.target.pattern) (out.target as any).pattern = rule.target.pattern;
    if (rule.fallback) out.fallback = rule.fallback;
    if (rule.message) out.message = rule.message;
    return out;
  });
}

// ─── Unix socket rules ────────────────────────────────────

function serializeUnixSocketRules(rules: UnixSocketRule[]): Record<string, unknown>[] {
  return rules.map((rule) => {
    const out: Record<string, unknown> = {
      name: rule.name,
      paths: rule.paths,
      decision: rule.decision,
    };
    if (rule.operations) out.operations = rule.operations;
    if (rule.message) out.message = rule.message;
    return out;
  });
}

// ─── Resource limits ───────────────────────────────────────

function serializeResourceLimits(limits: ResourceLimits): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  if (limits.maxMemoryMb !== undefined) out.max_memory_mb = limits.maxMemoryMb;
  if (limits.cpuQuotaPercent !== undefined) out.cpu_quota_percent = limits.cpuQuotaPercent;
  if (limits.pidsMax !== undefined) out.pids_max = limits.pidsMax;
  if (limits.commandTimeout !== undefined) out.command_timeout = limits.commandTimeout;
  if (limits.sessionTimeout !== undefined) out.session_timeout = limits.sessionTimeout;
  if (limits.idleTimeout !== undefined) out.idle_timeout = limits.idleTimeout;
  return out;
}

// ─── Audit settings ────────────────────────────────────────

function serializeAuditSettings(settings: AuditSettings): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  if (settings.logAllowed !== undefined) out.log_allowed = settings.logAllowed;
  if (settings.logDenied !== undefined) out.log_denied = settings.logDenied;
  if (settings.logApproved !== undefined) out.log_approved = settings.logApproved;
  if (settings.includeStdout !== undefined) out.include_stdout = settings.includeStdout;
  if (settings.includeStderr !== undefined) out.include_stderr = settings.includeStderr;
  return out;
}

// ─── Secret providers ─────────────────────────────────────

function serializeVaultAuth(auth: VaultAuth): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  if (auth.method) out.method = auth.method;
  if (auth.token) out.token = auth.token;
  if (auth.tokenRef) out.token_ref = auth.tokenRef;
  if (auth.roleId) out.role_id = auth.roleId;
  if (auth.roleIdRef) out.role_id_ref = auth.roleIdRef;
  if (auth.secretId) out.secret_id = auth.secretId;
  if (auth.secretIdRef) out.secret_id_ref = auth.secretIdRef;
  if (auth.kubeRole) out.kube_role = auth.kubeRole;
  if (auth.kubeMountPath) out.kube_mount_path = auth.kubeMountPath;
  if (auth.kubeTokenPath) out.kube_token_path = auth.kubeTokenPath;
  return out;
}

function serializeProviders(providers: Record<string, SecretProvider>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [name, p] of Object.entries(providers)) {
    const entry: Record<string, unknown> = { type: p.type };
    switch (p.type) {
      case 'keyring':
        break;
      case 'vault':
        entry.address = p.address;
        if (p.namespace) entry.namespace = p.namespace;
        if (p.auth) entry.auth = serializeVaultAuth(p.auth);
        break;
      case 'aws-sm':
        entry.region = p.region;
        break;
      case 'gcp-sm':
        entry.project_id = p.projectId;
        break;
      case 'azure-kv':
        entry.vault_url = p.vaultUrl;
        break;
      case 'op':
        entry.server_url = p.serverUrl;
        if (p.apiKey) entry.api_key = p.apiKey;
        if (p.apiKeyRef) entry.api_key_ref = p.apiKeyRef;
        break;
    }
    out[name] = entry;
  }
  return out;
}

// ─── HTTP services ────────────────────────────────────────

function serializeHttpServices(services: HttpService[]): Record<string, unknown>[] {
  return services.map((svc) => {
    const out: Record<string, unknown> = { name: svc.name, upstream: svc.upstream };
    if (svc.exposeAs) out.expose_as = svc.exposeAs;
    if (svc.aliases) out.aliases = svc.aliases;
    if (svc.allowDirect !== undefined) out.allow_direct = svc.allowDirect;
    if (svc.default) out.default = svc.default;
    if (svc.rules) {
      out.rules = svc.rules.map((rule) => {
        const r: Record<string, unknown> = {
          name: rule.name,
          paths: rule.paths,
          decision: rule.decision,
        };
        if (rule.methods) r.methods = rule.methods;
        if (rule.message) r.message = rule.message;
        if (rule.timeout) r.timeout = rule.timeout;
        return r;
      });
    }
    if (svc.secret) {
      out.secret = { ref: svc.secret.ref, format: svc.secret.format };
    }
    if (svc.inject) {
      const inj: Record<string, unknown> = {};
      if (svc.inject.header) {
        inj.header = { name: svc.inject.header.name, template: svc.inject.header.template };
      }
      out.inject = inj;
    }
    if (svc.scrubResponse !== undefined) out.scrub_response = svc.scrubResponse;
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

  if (policy.envPolicy) {
    doc.env_policy = serializeEnvPolicy(policy.envPolicy);
  }

  if (policy.signalRules && policy.signalRules.length > 0) {
    doc.signal_rules = serializeSignalRules(policy.signalRules);
  }

  if (policy.unixSocketRules && policy.unixSocketRules.length > 0) {
    doc.unix_socket_rules = serializeUnixSocketRules(policy.unixSocketRules);
  }

  if (policy.resourceLimits) {
    doc.resource_limits = serializeResourceLimits(policy.resourceLimits);
  }

  if (policy.auditSettings) {
    doc.audit = serializeAuditSettings(policy.auditSettings);
  }

  if (policy.providers && Object.keys(policy.providers).length > 0) {
    doc.providers = serializeProviders(policy.providers);
  }

  if (policy.httpServices && policy.httpServices.length > 0) {
    doc.http_services = serializeHttpServices(policy.httpServices);
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
