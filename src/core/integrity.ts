import { IntegrityError } from './errors.js';

export const PINNED_VERSION = '0.16.2';

export const CHECKSUMS: Record<string, Record<string, string>> = {
  '0.16.2': {
    linux_amd64:
      '7ff357066a61694626d4c19afa92fdf368318bced9be90391cc2f3808976f995',
    linux_arm64:
      'a48b3e4a60804cca98326619a68409e8ee83556d69ee2cf5d574e4361e0c19c6',
  },
  '0.15.0': {
    linux_amd64:
      '89f7ebbfd75ffd961245ec62b2602fd0cc387740502ac858dbc39c367c5699c5',
    linux_arm64:
      '3fabbd749f9e98fb9f96ddfc94c389a6868cda7ed3668daa8440c39ceec85f3b',
  },
};

/**
 * Returns the checksum to verify against.
 * If `override` is provided, returns it directly.
 * Otherwise looks up the checksum in the pinned CHECKSUMS map.
 * Throws IntegrityError if no checksum is found.
 */
export function getChecksum(
  version: string,
  arch: string,
  override?: string,
): string {
  if (override) {
    return override;
  }

  const versionChecksums = CHECKSUMS[version];
  if (versionChecksums && versionChecksums[arch]) {
    return versionChecksums[arch];
  }

  throw new IntegrityError({
    expected: '',
    actual: '',
    message: `No pinned checksum for agentsh v${version}. Provide \`agentshChecksum\` explicitly or use \`skipIntegrityCheck: true\`.`,
  });
}

/**
 * Returns an array of shell commands to try for computing SHA-256 checksums.
 * Each command extracts just the hex hash value from the given file.
 */
export function buildVerifyCommand(filePath: string): string[] {
  return [
    `sha256sum "${filePath}" | awk '{print $1}'`,
    `shasum -a 256 "${filePath}" | awk '{print $1}'`,
    `openssl dgst -sha256 "${filePath}" | awk '{print $NF}'`,
  ];
}

/**
 * Returns the download URL for the agentsh binary.
 * If `overrideUrl` is provided, returns it directly.
 * Otherwise returns the default GitHub releases URL.
 */
export function binaryUrl(
  version: string,
  arch: string,
  overrideUrl?: string,
): string {
  if (overrideUrl) {
    return overrideUrl;
  }

  return `https://github.com/canyonroad/agentsh/releases/download/v${version}/agentsh_${version}_${arch}.tar.gz`;
}
