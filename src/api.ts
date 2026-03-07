import type {
  SandboxAdapter,
  SecuredSandbox,
  SecureConfig,
  CreateSandboxConfig,
} from './core/types.js';
import { provision } from './core/provision.js';
import { createSecuredSandbox } from './core/runtime.js';
import { MissingPeerDependencyError } from './core/errors.js';

export async function secureSandbox(
  adapter: SandboxAdapter,
  config?: SecureConfig,
): Promise<SecuredSandbox> {
  const resolvedConfig = config ?? {};
  const { sessionId, securityMode } = await provision(adapter, {
    workspace: '/workspace',
    ...resolvedConfig,
  });
  return createSecuredSandbox(adapter, sessionId, securityMode);
}

export async function createSandbox(
  config?: CreateSandboxConfig,
): Promise<SecuredSandbox> {
  let Sandbox: any;
  try {
    const mod = await import('@vercel/sandbox');
    Sandbox = mod.Sandbox;
  } catch {
    throw new MissingPeerDependencyError({
      packageName: '@vercel/sandbox',
      versionRange: '^1.0.0',
    });
  }

  const {
    runtime = 'node24',
    timeout = 300_000,
    vcpus = 2,
    snapshot,
    ...secureConfig
  } = config ?? {};

  const createOpts: Record<string, unknown> = { runtime, timeout, vcpus };
  if (snapshot) createOpts.snapshot = snapshot;

  const sandbox = await Sandbox.create(createOpts);
  const { vercel } = await import('./adapters/vercel.js');

  return secureSandbox(vercel(sandbox), {
    ...secureConfig,
    installStrategy: snapshot ? 'preinstalled' : secureConfig.installStrategy,
  });
}
