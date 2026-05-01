/**
 * Freestyle account cleanup: delete VMs that are stopped or suspended.
 *
 * Background: Vm.stop() in the Freestyle SDK shuts the VM down but leaves it
 * in the account, counting toward the active-VM plan limit. Test runs that
 * crashed before deleting their VM, or older runs that called stop() instead
 * of vms.delete(), accumulate over time and eventually trip
 * `VmLimitExceededError`.
 *
 * This script lists all VMs in the account, prints them with their state,
 * then deletes everything in state `stopped` or `suspended`. Running VMs are
 * never touched.
 *
 * Run: `npx tsx scripts/freestyle-cleanup.ts` (loads .env.e2e for FREESTYLE_API_KEY)
 *      `npx tsx scripts/freestyle-cleanup.ts --dry-run` to preview without deleting.
 */
import { config } from 'dotenv';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
config({ path: resolve(__dirname, '../.env.e2e') });

const FREESTYLE_API_KEY = process.env.FREESTYLE_API_KEY;
if (!FREESTYLE_API_KEY) {
  console.error('FREESTYLE_API_KEY missing (set in .env.e2e or env)');
  process.exit(1);
}

const dryRun = process.argv.includes('--dry-run');

const fsMod = await import('freestyle-sandboxes');
const FreestyleClass = (fsMod as any).Freestyle;
const fsClient = new FreestyleClass({ apiKey: FREESTYLE_API_KEY });

const list = await fsClient.vms.list();
const vms: Array<{ id: string; state: string; createdAt?: string | null }> = list.vms ?? [];

console.log(`Total VMs: ${vms.length}`);
console.log(`  running: ${list.runningCount ?? '?'}`);
console.log(`  starting: ${list.startingCount ?? '?'}`);
console.log(`  suspended: ${list.suspendedCount ?? '?'}`);
console.log(`  stopped: ${list.stoppedCount ?? '?'}`);
console.log();

const deletable = vms.filter(v => v.state === 'stopped' || v.state === 'suspended');

if (deletable.length === 0) {
  console.log('No stopped or suspended VMs to delete.');
  process.exit(0);
}

console.log(`Will ${dryRun ? 'preview' : 'delete'} ${deletable.length} VM(s):`);
for (const vm of deletable) {
  console.log(`  ${vm.id}  state=${vm.state}  createdAt=${vm.createdAt ?? '?'}`);
}
console.log();

if (dryRun) {
  console.log('--dry-run: nothing deleted.');
  process.exit(0);
}

let ok = 0;
let failed = 0;
for (const vm of deletable) {
  try {
    await fsClient.vms.delete({ vmId: vm.id });
    console.log(`  ✓ deleted ${vm.id}`);
    ok++;
  } catch (err: any) {
    console.log(`  ✗ ${vm.id}: ${err?.message ?? err}`);
    failed++;
  }
}

console.log();
console.log(`Deleted ${ok}; failed ${failed}.`);
process.exit(failed > 0 ? 1 : 0);
