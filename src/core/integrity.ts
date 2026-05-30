import { IntegrityError } from './errors.js';

export const PINNED_VERSION = '0.20.3';

export const CHECKSUMS: Record<string, Record<string, string>> = {
  '0.20.3': {
    linux_amd64:
      '5d59340d86ed5cba41088ca22ee99a1374222138be552317b8a75eb4800f2770',
    linux_arm64:
      '3687caaf4454b592d54a08703848fbce5dd9dca448757cb81dca065e01b09176',
  },
  '0.20.3-rc17': {
    linux_amd64:
      '9fb35bf88728532aeeac4c731265cb7bced1f35ed4926a4b715191263b37223c',
    linux_arm64:
      '895a2fcbc94b712507d748b5b9ae47caf013f74d6e6c868d79493dc545c1b089',
  },
  '0.20.1': {
    linux_amd64:
      '7e8d49c6774e1945c681525c7f3b5e1506043c6ce50e7412c7708f99661418ed',
    linux_arm64:
      '0345c604f0fcf1838b649ed4059b13202652e8a27a9b389902f733087835d826',
  },
  '0.20.1-rc1': {
    linux_amd64:
      '1df831e885789fda3dd694654f28299385d8f5df3425844d0aa7eabaf0a4fcc1',
    linux_arm64:
      '6a4324b07a5e570b945e6cab7fd3602c9e2fdb281439665505e0234ba4babe8a',
  },
  '0.20.0': {
    linux_amd64:
      'eb6da1554296a56a6e6009f0ba995bc4ba6b7eac4063981308d4955715fb948b',
    linux_arm64:
      '9ff2b3b689369199808fe41ddb0898e56a619a6d0a5a4adc0cfca718dd346aa3',
  },
  '0.20.0-rc1': {
    linux_amd64:
      'f7fe3dc8f9375f3ea3319b6da62ccd4320180d5cf5430fd0148b7bc1e5d9ae5c',
    linux_arm64:
      '5e54802c90f3119c43122f7d5602e58aafe0a14e90b8bd935fdad0a331d30044',
  },
  '0.19.3': {
    linux_amd64:
      '9070c67dc9d78b5bee11fe4a071eb04b5f20ea9192727d6ed214f31f55b533db',
    linux_arm64:
      '23e22059403ebea3f2ed7cc5932ad9917bd6641bb5f3eb3f5b1845555b98b2a6',
  },
  '0.19.3-rc1': {
    linux_amd64:
      '92de8b1a74d9b953f9d1e2cd6212e0f7e5e35f2d74f07f93715dedad9f11399c',
    linux_arm64:
      'ad3aa33be4365d860445f1fda8baad41a394e61d90b5fea89a1680ebd6cb1080',
  },
  '0.19.2': {
    linux_amd64:
      '7e5b77209c6b00aab06802fb278078b3c581bdd0b57d10dc9297de80cf9f589a',
    linux_arm64:
      '30a301e93ef42cad7c47ac98c609970c77e5065b6a4b9f819d6462b2e378fc50',
  },
  '0.19.1': {
    linux_amd64:
      '75f5318c63385fd2f87ad32dbb21dfd829e0a39415fd16a9a4140065a391aad4',
    linux_arm64:
      '3f23c42bdb92fe4fe22df9d819ea46f43ea86493822f1a7ae55a910f1cfbcda0',
  },
  '0.19.0': {
    linux_amd64:
      '04c1b0e958a6e9027fc85d4625bec765e459f191dc16c4c5a04468c867f71d85',
    linux_arm64:
      '89cecae90e6511cf96019cca948e3b5142dce329349141eb838979a243dda9cd',
  },
  '0.18.3': {
    linux_amd64:
      '07612c7062e843d0375519c08ac0c590cba99c990c0350ee4bade1fca34f0ddd',
    linux_arm64:
      '22bc02e32877cb75df45a2a0474cc0afe87709634d6f6ed2561b9bafdbc75e81',
  },
  '0.18.2': {
    linux_amd64:
      '5b277f4565b8beecee1011c7683f58b51ac25ae8cc7c7d2e1f3f7433bdd3b825',
    linux_arm64:
      '2dcbc30ee9af3b8ac0212d35ec855c3fe038febf503fc3dcf7a519ffc6d0d44d',
  },
  '0.18.2-rc1': {
    linux_amd64:
      '6b9d952c8761d4e712a04fd9bf8235a270f0499e130ebfcf7e454f08886f9681',
    linux_arm64:
      '05a4e51ef47fdfb1b426804343da7922a5338ad9ff22ee894b5d8b78f60cf1a1',
  },
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
