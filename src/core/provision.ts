import type {
  SandboxAdapter,
  SecureConfig,
  SecurityMode,
  ExecResult,
} from './types.js';
import {
  getChecksum,
  buildVerifyCommand,
  binaryUrl,
  PINNED_VERSION,
} from './integrity.js';
import { generateServerConfig } from './config.js';
import { ProvisioningError, IntegrityError } from './errors.js';
import { serializePolicy, systemPolicyYaml } from '../policies/serialize.js';
import { agentDefault } from '../policies/presets.js';
import { validatePolicy } from '../policies/schema.js';
import { getTraceparent } from './traceparent.js';

// ─── Security mode ordering (strongest to weakest) ────────────

const SECURITY_MODE_RANK: Record<SecurityMode, number> = {
  full: 4,
  landlock: 3,
  'landlock-only': 2,
  minimal: 1,
};

function isWeakerThan(detected: SecurityMode, required: SecurityMode): boolean {
  return SECURITY_MODE_RANK[detected] < SECURITY_MODE_RANK[required];
}

// ─── Architecture mapping ─────────────────────────────────────

function mapArch(uname: string): 'linux_amd64' | 'linux_arm64' {
  const trimmed = uname.trim();
  if (trimmed === 'x86_64') return 'linux_amd64';
  if (trimmed === 'aarch64') return 'linux_arm64';
  throw new ProvisioningError({
    phase: 'install',
    command: 'uname -m',
    stderr: `Unsupported architecture: ${trimmed}`,
  });
}

// ─── Helper: check if binary exists ───────────────────────────

const AGENTSH_PATHS = ['/usr/local/bin/agentsh', '/usr/bin/agentsh'];

async function binaryExists(adapter: SandboxAdapter): Promise<boolean> {
  for (const path of AGENTSH_PATHS) {
    const found = adapter.fileExists
      ? await adapter.fileExists(path)
      : (await adapter.exec('test', ['-f', path])).exitCode === 0;
    if (found) return true;
  }
  return false;
}

// ─── Helper: sleep ────────────────────────────────────────────

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ─── Main provisioning function ───────────────────────────────

export interface ProvisionResult {
  sessionId: string;
  securityMode: SecurityMode;
  /** When true, the shell shim enforces policy — skip agentsh exec wrapper. */
  passthrough?: boolean;
}

export async function provision(
  adapter: SandboxAdapter,
  config: SecureConfig = {},
): Promise<ProvisionResult> {
  const {
    policy: rawPolicy,
    workspace = '/workspace',
    watchtower,
    installStrategy = 'download',
    agentshVersion = PINNED_VERSION,
    agentshArch: archOverride,
    agentshBinaryUrl,
    agentshChecksum,
    skipIntegrityCheck = false,
    minimumSecurityMode,
    realPaths: realPathsOverride,
    traceParent,
    policyName = 'policy',
    threatFeeds,
  } = config;

  // Resolve and validate policy
  const policy = rawPolicy ? validatePolicy(rawPolicy) : agentDefault();

  let securityMode: SecurityMode = 'full';

  if (installStrategy === 'running') {
    // agentsh is already fully provisioned and running with the shell shim
    // installed. Commands go through the shim automatically, so we don't
    // create a new session (which would deadlock the server via nested
    // agentsh connections). Instead, read the existing session ID from
    // the environment and use passthrough mode at runtime.
    //
    // Skip detectSecurityMode() — running `agentsh detect` inside a sandbox
    // where the shell shim is already installed would route the command
    // through agentsh's exec API, causing the server to try binding port
    // 18080 again ("address already in use"). Default to 'full' since
    // pre-provisioned environments typically have full capabilities.
    await healthCheck(adapter);

    securityMode = config.securityMode ?? 'full';

    if (minimumSecurityMode && isWeakerThan(securityMode, minimumSecurityMode)) {
      throw new ProvisioningError({
        phase: 'install',
        command: 'securityMode check',
        stderr: `Security mode '${securityMode}' is weaker than required '${minimumSecurityMode}'`,
      });
    }

    // Read the existing session ID from config or from the environment
    let sessionId = config.sessionId;
    if (!sessionId) {
      const envResult = await adapter.exec('sh', ['-c', 'echo $AGENTSH_SESSION_ID']);
      sessionId = envResult.stdout.trim();
    }
    if (!sessionId) {
      throw new ProvisioningError({
        phase: 'session',
        command: 'echo $AGENTSH_SESSION_ID',
        stderr: 'AGENTSH_SESSION_ID not set — running strategy requires a pre-created session',
      });
    }

    return { sessionId, securityMode, passthrough: true };
  }

  // ─── Phase 1: Binary Installation ───────────────────────────

  // Step 1: Check if binary exists
  const exists = await binaryExists(adapter);

  if (installStrategy === 'preinstalled') {
    if (!exists) {
      throw new ProvisioningError({
        phase: 'install',
        command: AGENTSH_PATHS.map(p => `test -f ${p}`).join(' || '),
        stderr: 'Binary not found but installStrategy is preinstalled',
      });
    }
    // Binary exists and strategy is preinstalled, skip to detect
  } else if (installStrategy === 'download' || installStrategy === 'upload') {
    // If binary already exists, skip installation but still detect
    if (!exists) {
      // Step 2: Detect architecture
      const arch =
        archOverride ?? await detectArch(adapter);

      if (installStrategy === 'download') {
        // Step 3a: Download
        await downloadBinary(adapter, agentshVersion, arch, agentshBinaryUrl);
      } else {
        // Step 3b: Upload
        await uploadBinary(adapter, agentshVersion, arch, agentshBinaryUrl);
      }

      // Step 4: Verify checksum
      if (!skipIntegrityCheck) {
        await verifyChecksum(
          adapter,
          agentshVersion,
          arch,
          agentshChecksum,
          '/tmp/agentsh.tar.gz',
        );
      }

      // Step 5: Install binaries (agentsh + agentsh-shell-shim + agentsh-unixwrap)
      const binaries = [
        { src: '/tmp/agentsh', dest: '/usr/local/bin/agentsh' },
        { src: '/tmp/agentsh-shell-shim', dest: '/usr/bin/agentsh-shell-shim' },
        { src: '/tmp/agentsh-unixwrap', dest: '/usr/local/bin/agentsh-unixwrap' },
      ];
      for (const { src, dest } of binaries) {
        const installResult = await adapter.exec(
          'install',
          ['-m', '0755', src, dest],
          { sudo: true },
        );
        if (installResult.exitCode !== 0) {
          throw new ProvisioningError({
            phase: 'install',
            command: `install -m 0755 ${src} ${dest}`,
            stderr: installResult.stderr,
          });
        }
      }
    }
  }

  // Step 5b: Detect security mode
  securityMode = await detectSecurityMode(adapter);

  // Check minimum security mode
  if (minimumSecurityMode && isWeakerThan(securityMode, minimumSecurityMode)) {
    throw new ProvisioningError({
      phase: 'install',
      command: 'agentsh detect --json',
      stderr: `Detected security mode '${securityMode}' is weaker than required '${minimumSecurityMode}'`,
    });
  }

  // Auto-enable realPaths when FUSE is available (full or landlock modes),
  // unless the user explicitly set it.
  const hasFuse = securityMode === 'full' || securityMode === 'landlock';
  const realPaths = realPathsOverride ?? hasFuse;

  // Step 6: Install shell shim
  const shimResult = await adapter.exec(
    'agentsh',
    [
      'shim', 'install-shell',
      '--root', '/',
      '--shim', '/usr/bin/agentsh-shell-shim',
      '--bash',
      '--i-understand-this-modifies-the-host',
    ],
    { sudo: true },
  );
  if (shimResult.exitCode !== 0) {
    throw new ProvisioningError({
      phase: 'install',
      command: 'agentsh shim install-shell',
      stderr: shimResult.stderr,
    });
  }

  // ─── Phase 2: Policy & Config ───────────────────────────────

  // Step 7: Create dirs and make writable for file writes
  const mkdirResult = await adapter.exec(
    'mkdir',
    ['-p', '/etc/agentsh/system'],
    { sudo: true },
  );
  if (mkdirResult.exitCode !== 0) {
    throw new ProvisioningError({
      phase: 'policy',
      command: 'mkdir -p /etc/agentsh/system',
      stderr: mkdirResult.stderr,
    });
  }

  // Temporarily make writable so adapter.writeFile (which may not support sudo) can write
  await adapter.exec('chmod', ['-R', '777', '/etc/agentsh/'], { sudo: true });

  await adapter.writeFile(
    '/etc/agentsh/system/policy.yml',
    systemPolicyYaml(),
    { sudo: true },
  );

  // Step 8: Write user policy
  await adapter.writeFile(
    '/etc/agentsh/policy.yml',
    serializePolicy(policy),
    { sudo: true },
  );

  // Step 9: Write server config
  const serverConfig = generateServerConfig({
    watchtower,
    realPaths,
    threatFeeds,
  });

  await adapter.writeFile('/etc/agentsh/config.yml', serverConfig, {
    sudo: true,
  });

  // Step 10: Set permissions
  const chmodDirResult = await adapter.exec(
    'find',
    ['/etc/agentsh', '-type', 'd', '-exec', 'chmod', '555', '{}', '+'],
    { sudo: true },
  );
  if (chmodDirResult.exitCode !== 0) {
    throw new ProvisioningError({
      phase: 'policy',
      command: 'find /etc/agentsh -type d -exec chmod 555 {} +',
      stderr: chmodDirResult.stderr,
    });
  }

  const chmodFileResult = await adapter.exec(
    'find',
    ['/etc/agentsh', '-type', 'f', '-exec', 'chmod', '444', '{}', '+'],
    { sudo: true },
  );
  if (chmodFileResult.exitCode !== 0) {
    throw new ProvisioningError({
      phase: 'policy',
      command: 'find /etc/agentsh -type f -exec chmod 444 {} +',
      stderr: chmodFileResult.stderr,
    });
  }

  const chownResult = await adapter.exec(
    'chown',
    ['-R', 'root:root', '/etc/agentsh/'],
    { sudo: true },
  );
  if (chownResult.exitCode !== 0) {
    throw new ProvisioningError({
      phase: 'policy',
      command: 'chown -R root:root /etc/agentsh/',
      stderr: chownResult.stderr,
    });
  }

  // ─── Phase 3: Server Startup ────────────────────────────────

  // Step 10b: Ensure workspace directory exists
  await adapter.exec('mkdir', ['-p', workspace], { sudo: true });

  // Step 11: Start server
  const serverResult = await adapter.exec(
    'agentsh',
    ['server', '--config', '/etc/agentsh/config.yml'],
    { detached: true, sudo: true },
  );
  if (serverResult.exitCode !== 0) {
    throw new ProvisioningError({
      phase: 'startup',
      command: 'agentsh server --config /etc/agentsh/config.yml',
      stderr: serverResult.stderr,
    });
  }

  // Step 12: Health check
  await healthCheck(adapter);

  // Step 13: Create session
  const sessionResult = await adapter.exec('agentsh', [
    'session',
    'create',
    '--workspace',
    workspace,
    '--policy',
    'policy',
  ]);
  if (sessionResult.exitCode !== 0) {
    throw new ProvisioningError({
      phase: 'session',
      command: 'agentsh session create',
      stderr: sessionResult.stderr,
    });
  }

  let sessionId: string;
  try {
    const sessionData = JSON.parse(sessionResult.stdout);
    sessionId = sessionData.session_id;
  } catch {
    // Fallback: parse text output like "Session session-xxx started"
    const match = sessionResult.stdout.match(/Session\s+(session-[^\s]+)/);
    if (match) {
      sessionId = match[1];
    } else {
      throw new ProvisioningError({
        phase: 'session',
        command: 'agentsh session create',
        stderr: `Failed to parse session output: ${sessionResult.stdout}`,
      });
    }
  }

  // Step 13b: Set trace context if traceParent is provided or OTEL span is active
  const effectiveTraceParent = traceParent ?? (await getTraceparent());
  if (effectiveTraceParent) {
    await adapter.exec('curl', [
      '-X',
      'PUT',
      `http://127.0.0.1:18080/sessions/${sessionId}/trace-context`,
      '-H',
      'Content-Type: application/json',
      '-d',
      JSON.stringify({ traceparent: effectiveTraceParent }),
    ]);
  }

  // ─── Phase 4: Handoff ───────────────────────────────────────

  // Step 14: Return result
  return { sessionId, securityMode };
}

// ─── Phase 1 helpers ──────────────────────────────────────────

async function detectArch(
  adapter: SandboxAdapter,
): Promise<'linux_amd64' | 'linux_arm64'> {
  const result = await adapter.exec('uname', ['-m']);
  if (result.exitCode !== 0) {
    throw new ProvisioningError({
      phase: 'install',
      command: 'uname -m',
      stderr: result.stderr,
    });
  }
  return mapArch(result.stdout);
}

async function downloadBinary(
  adapter: SandboxAdapter,
  version: string,
  arch: string,
  overrideUrl?: string,
): Promise<void> {
  const url = binaryUrl(version, arch, overrideUrl);

  // Try curl first
  const curlResult = await adapter.exec('curl', [
    '-fsSL',
    url,
    '-o',
    '/tmp/agentsh.tar.gz',
  ]);

  if (curlResult.exitCode !== 0) {
    // Fallback to wget (may not be available on all platforms)
    let wgetResult: ExecResult;
    try {
      wgetResult = await adapter.exec('wget', [
        '-q',
        url,
        '-O',
        '/tmp/agentsh.tar.gz',
      ]);
    } catch {
      throw new ProvisioningError({
        phase: 'install',
        command: `curl -fsSL ${url} -o /tmp/agentsh.tar.gz`,
        stderr: curlResult.stderr || 'Download failed (curl failed, wget not available)',
      });
    }
    if (wgetResult.exitCode !== 0) {
      throw new ProvisioningError({
        phase: 'install',
        command: `wget -q ${url} -O /tmp/agentsh.tar.gz`,
        stderr: wgetResult.stderr,
      });
    }
  }

  // Extract
  const tarResult = await adapter.exec('tar', [
    'xz',
    '-C',
    '/tmp/',
    '-f',
    '/tmp/agentsh.tar.gz',
  ]);
  if (tarResult.exitCode !== 0) {
    throw new ProvisioningError({
      phase: 'install',
      command: 'tar xz -C /tmp/ -f /tmp/agentsh.tar.gz',
      stderr: tarResult.stderr,
    });
  }
}

async function uploadBinary(
  adapter: SandboxAdapter,
  version: string,
  arch: string,
  overrideUrl?: string,
): Promise<void> {
  const url = binaryUrl(version, arch, overrideUrl);

  // Download on host side using fetch (Node 18+)
  const response = await fetch(url);
  if (!response.ok) {
    throw new ProvisioningError({
      phase: 'install',
      command: `fetch ${url}`,
      stderr: `HTTP ${response.status}: ${response.statusText}`,
    });
  }

  const buffer = Buffer.from(await response.arrayBuffer());

  // Upload tarball to sandbox and extract
  await adapter.writeFile('/tmp/agentsh.tar.gz', buffer);
  const tarResult = await adapter.exec('tar', [
    'xz',
    '-C',
    '/tmp/',
    '-f',
    '/tmp/agentsh.tar.gz',
  ]);
  if (tarResult.exitCode !== 0) {
    throw new ProvisioningError({
      phase: 'install',
      command: 'tar xz -C /tmp/ -f /tmp/agentsh.tar.gz',
      stderr: tarResult.stderr,
    });
  }
}

async function verifyChecksum(
  adapter: SandboxAdapter,
  version: string,
  arch: string,
  checksumOverride: string | undefined,
  filePath: string,
): Promise<void> {
  const expected = getChecksum(version, arch, checksumOverride);
  const commands = buildVerifyCommand(filePath);

  let actual: string | undefined;

  for (const cmd of commands) {
    const result = await adapter.exec('sh', ['-c', cmd]);
    if (result.exitCode === 0 && result.stdout.trim()) {
      actual = result.stdout.trim();
      break;
    }
  }

  if (actual === undefined) {
    throw new ProvisioningError({
      phase: 'install',
      command: 'sha256sum / shasum / openssl',
      stderr: 'No checksum tool available in sandbox',
    });
  }

  if (actual !== expected) {
    throw new IntegrityError({
      expected,
      actual,
      message: `Checksum mismatch: expected ${expected}, got ${actual}`,
    });
  }
}

async function detectSecurityMode(
  adapter: SandboxAdapter,
): Promise<SecurityMode> {
  const result = await adapter.exec('agentsh', ['detect', '--output', 'json']);
  if (result.exitCode !== 0) {
    throw new ProvisioningError({
      phase: 'install',
      command: 'agentsh detect --output json',
      stderr: result.stderr,
    });
  }

  // agentsh detect outputs JSON to stderr
  const jsonOutput = result.stderr || result.stdout;
  let parsed: { security_mode: string };
  try {
    parsed = JSON.parse(jsonOutput);
  } catch {
    throw new ProvisioningError({
      phase: 'install',
      command: 'agentsh detect --output json',
      stderr: `Failed to parse detect JSON: ${jsonOutput.slice(0, 200)}`,
    });
  }

  const mode = parsed.security_mode;
  const validModes: SecurityMode[] = ['full', 'landlock', 'landlock-only', 'minimal'];
  if (!validModes.includes(mode as SecurityMode)) {
    throw new ProvisioningError({
      phase: 'install',
      command: 'agentsh detect --output json',
      stderr: `Unknown security mode: '${mode}'`,
    });
  }
  return mode as SecurityMode;
}

async function healthCheck(adapter: SandboxAdapter): Promise<void> {
  const maxRetries = 10;
  const delayMs = 500;

  for (let i = 0; i < maxRetries; i++) {
    const result = await adapter.exec('curl', [
      '-sf',
      'http://127.0.0.1:18080/health',
    ]);
    if (result.exitCode === 0) {
      return;
    }
    if (i < maxRetries - 1) {
      await sleep(delayMs);
    }
  }

  throw new ProvisioningError({
    phase: 'startup',
    command: 'curl http://127.0.0.1:18080/health',
    stderr: 'Health check failed after 10 attempts',
  });
}
