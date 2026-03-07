// Main API functions
export { secureSandbox, createSandbox } from './api.js';

// Core types
export type {
  SecuredSandbox,
  SandboxAdapter,
  ExecResult,
  ReadFileResult,
  WriteFileResult,
  SecureConfig,
  CreateSandboxConfig,
  SecurityMode,
  InstallStrategy,
} from './core/types.js';

// Policy type
export type { PolicyDefinition } from './policies/schema.js';

// Error classes
export {
  AgentSHError,
  PolicyValidationError,
  MissingPeerDependencyError,
  IncompatibleProviderVersionError,
  ProvisioningError,
  IntegrityError,
  RuntimeError,
} from './core/errors.js';

// Namespaced re-exports
import * as policies from './policies/index.js';
import * as adapters from './adapters/index.js';
export { policies, adapters };
