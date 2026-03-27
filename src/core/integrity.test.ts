import { describe, it, expect } from 'vitest';
import { IntegrityError } from './errors.js';
import {
  CHECKSUMS,
  PINNED_VERSION,
  getChecksum,
  buildVerifyCommand,
  binaryUrl,
} from './integrity.js';

describe('CHECKSUMS', () => {
  it('has checksums for pinned version linux_amd64', () => {
    expect(CHECKSUMS[PINNED_VERSION]).toBeDefined();
    expect(CHECKSUMS[PINNED_VERSION]['linux_amd64']).toBeDefined();
  });

  it('has checksums for pinned version linux_arm64', () => {
    expect(CHECKSUMS[PINNED_VERSION]).toBeDefined();
    expect(CHECKSUMS[PINNED_VERSION]['linux_arm64']).toBeDefined();
  });

  it('has checksums for v0.16.2 linux_amd64', () => {
    expect(CHECKSUMS['0.16.2']['linux_amd64']).toBe(
      '7ff357066a61694626d4c19afa92fdf368318bced9be90391cc2f3808976f995',
    );
  });

  it('has checksums for v0.16.2 linux_arm64', () => {
    expect(CHECKSUMS['0.16.2']['linux_arm64']).toBe(
      'a48b3e4a60804cca98326619a68409e8ee83556d69ee2cf5d574e4361e0c19c6',
    );
  });
});

describe('getChecksum', () => {
  it('returns pinned checksum for known version+arch', () => {
    const checksum = getChecksum('0.16.2', 'linux_amd64');
    expect(checksum).toBe(
      '7ff357066a61694626d4c19afa92fdf368318bced9be90391cc2f3808976f995',
    );
  });

  it('returns override checksum when provided', () => {
    const override = 'deadbeef1234567890abcdef';
    const checksum = getChecksum('0.16.2', 'linux_amd64', override);
    expect(checksum).toBe(override);
  });

  it('throws IntegrityError for unknown version without override', () => {
    expect(() => getChecksum('0.99.0', 'linux_amd64')).toThrow(IntegrityError);
    expect(() => getChecksum('0.99.0', 'linux_amd64')).toThrow(
      'No pinned checksum for agentsh v0.99.0. Provide `agentshChecksum` explicitly or use `skipIntegrityCheck: true`.',
    );
  });
});

describe('buildVerifyCommand', () => {
  it('returns sha256sum command first', () => {
    const commands = buildVerifyCommand('/tmp/agentsh');
    expect(commands[0]).toContain('sha256sum');
    expect(commands[0]).toContain('/tmp/agentsh');
  });

  it('includes shasum fallback', () => {
    const commands = buildVerifyCommand('/tmp/agentsh');
    const shasumCmd = commands.find(
      (cmd) => cmd.includes('shasum') && cmd.includes('-a 256'),
    );
    expect(shasumCmd).toBeDefined();
    expect(shasumCmd).toContain('/tmp/agentsh');
  });

  it('includes openssl fallback', () => {
    const commands = buildVerifyCommand('/tmp/agentsh');
    const opensslCmd = commands.find(
      (cmd) => cmd.includes('openssl') && cmd.includes('sha256'),
    );
    expect(opensslCmd).toBeDefined();
    expect(opensslCmd).toContain('/tmp/agentsh');
  });
});

describe('binaryUrl', () => {
  it('returns default GitHub URL', () => {
    const url = binaryUrl('0.16.9', 'linux_amd64');
    expect(url).toBe(
      'https://github.com/canyonroad/agentsh/releases/download/v0.16.9/agentsh_0.16.9_linux_amd64.tar.gz',
    );
  });

  it('returns override URL when provided', () => {
    const override = 'https://my-mirror.example.com/agentsh.tar.gz';
    const url = binaryUrl('0.16.9', 'linux_amd64', override);
    expect(url).toBe(override);
  });
});
