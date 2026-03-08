import type {
  SandboxAdapter,
  SecuredSandbox,
  SecureConfig,
} from './core/types.js';
import { provision } from './core/provision.js';
import { createSecuredSandbox } from './core/runtime.js';

export async function secureSandbox(
  adapter: SandboxAdapter,
  config?: SecureConfig,
): Promise<SecuredSandbox> {
  const resolvedConfig = config ?? {};
  const { sessionId, securityMode, passthrough } = await provision(adapter, {
    workspace: '/workspace',
    ...resolvedConfig,
  });
  return createSecuredSandbox(adapter, sessionId, securityMode, { passthrough });
}
