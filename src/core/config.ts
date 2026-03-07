import yaml from 'js-yaml';

export interface ServerConfigOpts {
  workspace: string;
  watchtower?: string;
  enforceRedirects?: boolean;
  realPaths?: boolean;
}

export function generateServerConfig(opts: ServerConfigOpts): string {
  const config: Record<string, unknown> = {
    server: {
      http: {
        addr: '127.0.0.1:18080',
      },
    },
    auth: {
      type: 'none',
    },
    policies: {
      system_dir: '/etc/agentsh/system',
      dir: '/etc/agentsh',
      default: 'policy',
    },
    workspace: opts.workspace,
    sandbox: {
      enabled: true,
      allow_degraded: true,
    },
  };
  if (opts.watchtower) config.watchtower = opts.watchtower;
  if (opts.enforceRedirects) config.enforce_redirects = true;
  if (opts.realPaths) config.real_paths = true;
  return yaml.dump(config, { lineWidth: -1 });
}
