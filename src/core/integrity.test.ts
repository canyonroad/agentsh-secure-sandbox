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

  it('has checksums for v0.15.0 linux_amd64', () => {
    expect(CHECKSUMS['0.15.0']['linux_amd64']).toBe(
      '89f7ebbfd75ffd961245ec62b2602fd0cc387740502ac858dbc39c367c5699c5',
    );
  });

  it('has checksums for v0.15.0 linux_arm64', () => {
    expect(CHECKSUMS['0.15.0']['linux_arm64']).toBe(
      '3fabbd749f9e98fb9f96ddfc94c389a6868cda7ed3668daa8440c39ceec85f3b',
    );
  });
});

describe('getChecksum', () => {
  it('returns pinned checksum for known version+arch', () => {
    const checksum = getChecksum('0.15.0', 'linux_amd64');
    expect(checksum).toBe(
      '89f7ebbfd75ffd961245ec62b2602fd0cc387740502ac858dbc39c367c5699c5',
    );
  });

  it('returns override checksum when provided', () => {
    const override = 'deadbeef1234567890abcdef';
    const checksum = getChecksum('0.15.0', 'linux_amd64', override);
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
    const url = binaryUrl('0.16.2', 'linux_amd64');
    expect(url).toBe(
      'https://github.com/canyonroad/agentsh/releases/download/v0.16.2/agentsh_0.16.2_linux_amd64.tar.gz',
    );
  });

  it('returns override URL when provided', () => {
    const override = 'https://my-mirror.example.com/agentsh.tar.gz';
    const url = binaryUrl('0.16.2', 'linux_amd64', override);
    expect(url).toBe(override);
  });
});
