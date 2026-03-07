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
  it('has checksums for v0.14.0 linux_amd64', () => {
    expect(CHECKSUMS['0.14.0']).toBeDefined();
    expect(CHECKSUMS['0.14.0']['linux_amd64']).toBe(
      '2ab8ba0d6637fe1a5badf840c3db197161a6f9865d721ed216029d229b1b9bbc',
    );
  });

  it('has checksums for v0.14.0 linux_arm64', () => {
    expect(CHECKSUMS['0.14.0']).toBeDefined();
    expect(CHECKSUMS['0.14.0']['linux_arm64']).toBe(
      '929d18dd9fe36e9b2fa830d7ae64b4fb481853e743ade8674fcfcdc73470ed53',
    );
  });
});

describe('getChecksum', () => {
  it('returns pinned checksum for known version+arch', () => {
    const checksum = getChecksum('0.14.0', 'linux_amd64');
    expect(checksum).toBe(
      '2ab8ba0d6637fe1a5badf840c3db197161a6f9865d721ed216029d229b1b9bbc',
    );
  });

  it('returns override checksum when provided', () => {
    const override = 'deadbeef1234567890abcdef';
    const checksum = getChecksum('0.14.0', 'linux_amd64', override);
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
    const url = binaryUrl('0.14.0', 'linux_amd64');
    expect(url).toBe(
      'https://github.com/canyonroad/agentsh/releases/download/v0.14.0/agentsh_linux_amd64.tar.gz',
    );
  });

  it('returns override URL when provided', () => {
    const override = 'https://my-mirror.example.com/agentsh.tar.gz';
    const url = binaryUrl('0.14.0', 'linux_amd64', override);
    expect(url).toBe(override);
  });
});
