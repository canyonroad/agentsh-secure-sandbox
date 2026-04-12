import { IntegrityError } from './errors.js';

export const PINNED_VERSION = '0.18.0';

export const CHECKSUMS: Record<string, Record<string, string>> = {
  '0.18.0': {
    linux_amd64:
      'da21c4009af236cd51d07649d3c2d31d947a8aa52933e35ea780dbbfa328263f',
    linux_arm64:
      '52f50f5bb12f8730e832f3bf683a44178eb1db0d9b49b9ddc64740e41b0963fd',
  },
  '0.17.0': {
    linux_amd64:
      'f8b710e29a45e104b93dd922540bd877762d1c68005a62c871216055b6db82b4',
    linux_arm64:
      '4de3338f5d060d289dfbbf77c9172a573f4c06ca6f725fa619e408d75b17bd73',
  },
  '0.16.9': {
    linux_amd64:
      '37b7be738291e90957a13653c5bb60b3cbbf9ab5abbc932e00e679a431f9064e',
    linux_arm64:
      '4a8e29457241a329bca09d45830542de1c1c98976332234294a14d818c38fd72',
  },
  '0.16.2': {
    linux_amd64:
      '7ff357066a61694626d4c19afa92fdf368318bced9be90391cc2f3808976f995',
    linux_arm64:
      'a48b3e4a60804cca98326619a68409e8ee83556d69ee2cf5d574e4361e0c19c6',
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
