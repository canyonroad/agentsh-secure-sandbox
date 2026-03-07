import { describe, it, expect } from 'vitest';
import yaml from 'js-yaml';
import { generateServerConfig } from './config.js';

describe('generateServerConfig', () => {
  it('generates valid YAML with policy dirs', () => {
    const result = generateServerConfig({ workspace: '/workspace' });
    const parsed = yaml.load(result) as any;
    expect(parsed.policies.system_dir).toBe('/etc/agentsh/system');
    expect(parsed.policies.dir).toBe('/etc/agentsh');
    expect(parsed.policies.default).toBe('policy');
  });

  it('includes workspace path', () => {
    const result = generateServerConfig({ workspace: '/home/daytona' });
    const parsed = yaml.load(result) as any;
    expect(parsed.workspace).toBe('/home/daytona');
  });

  it('includes watchtower when provided', () => {
    const result = generateServerConfig({ workspace: '/workspace', watchtower: 'https://watchtower.example.com' });
    const parsed = yaml.load(result) as any;
    expect(parsed.watchtower).toBe('https://watchtower.example.com');
  });

  it('omits watchtower when not provided', () => {
    const result = generateServerConfig({ workspace: '/workspace' });
    const parsed = yaml.load(result) as any;
    expect(parsed.watchtower).toBeUndefined();
  });

  it('includes enforceRedirects when true', () => {
    const result = generateServerConfig({ workspace: '/workspace', enforceRedirects: true });
    const parsed = yaml.load(result) as any;
    expect(parsed.enforce_redirects).toBe(true);
  });

  it('includes realPaths when true', () => {
    const result = generateServerConfig({ workspace: '/workspace', realPaths: true });
    const parsed = yaml.load(result) as any;
    expect(parsed.real_paths).toBe(true);
  });

  it('omits enforce_redirects and real_paths when not set', () => {
    const result = generateServerConfig({ workspace: '/workspace' });
    const parsed = yaml.load(result) as any;
    expect(parsed.enforce_redirects).toBeUndefined();
    expect(parsed.real_paths).toBeUndefined();
  });
});
