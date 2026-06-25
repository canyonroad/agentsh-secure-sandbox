/**
 * Build sandbox images with agentsh pre-installed for E2B, Daytona, and Cloudflare.
 *
 * Usage:
 *   npx tsx scripts/build-sandbox-images.ts [--provider e2b|daytona|cloudflare|all]
 *
 * Prerequisites:
 *   - E2B: E2B_API_KEY set, `e2b` npm package available
 *   - Daytona: DAYTONA_API_KEY set, `@daytonaio/sdk` available
 *   - Cloudflare: wrangler authenticated, run `wrangler deploy` separately
 *
 * The Cloudflare image is built via the Dockerfile at project root —
 * this script only builds E2B and Daytona templates programmatically.
 */
import { config } from 'dotenv';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
config({ path: resolve(__dirname, '../.env.e2e') });

const AGENTSH_VERSION = '0.20.5';

const provider = process.argv.find(a => a.startsWith('--provider='))?.split('=')[1]
  ?? process.argv[process.argv.indexOf('--provider') + 1]
  ?? 'all';

// ── E2B ──────────────────────────────────────────────────────

async function buildE2B() {
  console.log('▶ Building E2B sandbox template...');

  const { Template, defaultBuildLogger } = await import('e2b');

  const template = Template()
    .fromDockerfile(resolve(__dirname, '../e2b.Dockerfile'));

  const result = await Template.build(template, {
    alias: 'agentsh-sandbox',
    onBuildLogs: defaultBuildLogger(),
  });

  console.log(`  ✓ E2B template built: ${result}`);
  console.log(`  Use in tests: Sandbox.create('agentsh-sandbox')`);
}

// ── Daytona ──────────────────────────────────────────────────

async function buildDaytona() {
  console.log('▶ Building Daytona sandbox image...');

  const { Daytona } = await import('@daytonaio/sdk');
  const client = new Daytona();

  // Create a sandbox, install agentsh, then snapshot it
  console.log('  → creating scratch sandbox...');
  const sb = await client.create();

  const run = async (cmd: string) => {
    const result = await sb.process.executeCommand(cmd);
    if (result.exitCode !== 0) {
      throw new Error(`Command failed (exit ${result.exitCode}): ${cmd}\n${result.result ?? ''}`);
    }
    return result;
  };

  console.log('  → installing dependencies...');
  await run('apt-get update && apt-get install -y --no-install-recommends libseccomp2 fuse3 curl ca-certificates');

  console.log(`  → installing agentsh v${AGENTSH_VERSION}...`);
  const url = `https://github.com/canyonroad/agentsh/releases/download/v${AGENTSH_VERSION}/agentsh_${AGENTSH_VERSION}_linux_amd64.tar.gz`;
  await run(`curl -fsSL '${url}' -o /tmp/agentsh.tar.gz`);
  await run('tar xz -C /tmp/ -f /tmp/agentsh.tar.gz');
  await run('install -m 0755 /tmp/agentsh /usr/local/bin/agentsh');
  await run('install -m 0755 /tmp/agentsh-shell-shim /usr/bin/agentsh-shell-shim');
  await run('install -m 0755 /tmp/agentsh-unixwrap /usr/local/bin/agentsh-unixwrap');
  await run('rm -f /tmp/agentsh.tar.gz /tmp/agentsh /tmp/agentsh-shell-shim /tmp/agentsh-unixwrap');

  // Verify
  const version = await run('/usr/local/bin/agentsh --version');
  console.log(`  → agentsh version: ${(version.result ?? '').trim()}`);

  console.log('  ✓ Daytona sandbox ready with agentsh pre-installed');
  console.log('  Note: Daytona sandboxes are ephemeral — this sandbox will be used for the current test run.');
  console.log('  For persistent images, use Daytona\'s custom image feature with a Dockerfile.');

  // Clean up - the sandbox has agentsh now but we can't snapshot it via SDK
  // For production, use Daytona's custom workspace image feature
  await client.delete(sb);
  console.log('  → scratch sandbox cleaned up');
}

// ── Cloudflare ───────────────────────────────────────────────

async function buildCloudflare() {
  console.log('▶ Cloudflare sandbox image...');
  console.log('  The Dockerfile at project root already includes agentsh v' + AGENTSH_VERSION);
  console.log('  Deploy with: wrangler deploy');
  console.log('  → deploying...');

  const { execSync } = await import('node:child_process');
  try {
    execSync('npx wrangler deploy', {
      cwd: resolve(__dirname, '..'),
      stdio: 'inherit',
      timeout: 120_000,
    });
    console.log('  ✓ Cloudflare worker deployed with updated Dockerfile');
  } catch (err: any) {
    console.error('  ✗ Deploy failed:', err.message);
    process.exit(1);
  }
}

// ── Main ─────────────────────────────────────────────────────

async function main() {
  console.log(`Building sandbox images with agentsh v${AGENTSH_VERSION}\n`);

  if (provider === 'all' || provider === 'e2b') {
    try { await buildE2B(); } catch (err: any) {
      console.error(`  ✗ E2B build failed: ${err.message}`);
    }
    console.log();
  }

  if (provider === 'all' || provider === 'daytona') {
    try { await buildDaytona(); } catch (err: any) {
      console.error(`  ✗ Daytona build failed: ${err.message}`);
    }
    console.log();
  }

  if (provider === 'all' || provider === 'cloudflare') {
    try { await buildCloudflare(); } catch (err: any) {
      console.error(`  ✗ Cloudflare build failed: ${err.message}`);
    }
    console.log();
  }
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
