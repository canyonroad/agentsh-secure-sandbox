import { describe, it, expect } from 'vitest';
import yaml from 'js-yaml';
import { generateServerConfig, defaultThreatFeeds } from './config.js';

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

  it('includes default threat feeds when not specified', () => {
    const result = generateServerConfig({ workspace: '/workspace' });
    const parsed = yaml.load(result) as any;
    expect(parsed.threat_feeds.enabled).toBe(true);
    expect(parsed.threat_feeds.action).toBe('deny');
    expect(parsed.threat_feeds.feeds).toHaveLength(2);
    expect(parsed.threat_feeds.feeds[0].name).toBe('urlhaus');
    expect(parsed.threat_feeds.feeds[1].name).toBe('phishing');
    expect(parsed.threat_feeds.allowlist).toContain('registry.npmjs.org');
  });

  it('disables threat feeds when set to false', () => {
    const result = generateServerConfig({ workspace: '/workspace', threatFeeds: false });
    const parsed = yaml.load(result) as any;
    expect(parsed.threat_feeds).toBeUndefined();
  });

  it('uses custom threat feeds when provided', () => {
    const result = generateServerConfig({
      workspace: '/workspace',
      threatFeeds: {
        action: 'audit',
        feeds: [{ name: 'custom', url: 'https://example.com/list.txt', format: 'domain-list' }],
      },
    });
    const parsed = yaml.load(result) as any;
    expect(parsed.threat_feeds.action).toBe('audit');
    expect(parsed.threat_feeds.feeds).toHaveLength(1);
    expect(parsed.threat_feeds.feeds[0].name).toBe('custom');
    expect(parsed.threat_feeds.allowlist).toBeUndefined();
  });
});

describe('defaultThreatFeeds', () => {
  it('has urlhaus and phishing feeds', () => {
    expect(defaultThreatFeeds.feeds).toHaveLength(2);
    expect(defaultThreatFeeds.feeds[0].name).toBe('urlhaus');
    expect(defaultThreatFeeds.feeds[0].url).toContain('abuse.ch');
    expect(defaultThreatFeeds.feeds[1].name).toBe('phishing');
    expect(defaultThreatFeeds.feeds[1].url).toContain('Phishing.Database');
  });

  it('has an allowlist with package registries', () => {
    expect(defaultThreatFeeds.allowlist).toContain('registry.npmjs.org');
    expect(defaultThreatFeeds.allowlist).toContain('pypi.org');
    expect(defaultThreatFeeds.allowlist).toContain('github.com');
  });
});
