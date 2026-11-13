/**
 * Write spec/vectors/withdrawals.json from the RDK's own withdrawalsTree (v2
 * leaves), so the Go circuit is tested against the chain's reference code.
 *   pnpm --filter @cloister/spike gen-vectors
 */
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { BLS12_381_SCALAR_MODULUS, withdrawalsTree } from "@qorechain/rdk";
import { CHAIN_ID, REPO_ROOT } from "@cloister/common";

const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");
const RECIPIENTS = [
  "qor12jmzemjntpkfr4ler3rdwpemrv3qg7pzxkpxkm",
  "qor1lyu0fnsxvxvwmhwnmuvrln9st4z70dap5mzkad",
  "qor16qg03qnndz6zzgz02ezda5agyrjwcyh4m3eh77",
];

const cases = [];
for (const rollupId of ["cloister", "cloister-dev-2"]) {
  for (let n = 1; n <= 4; n++) {
    const withdrawals = Array.from({ length: n }, (_, i) => ({
      recipient: RECIPIENTS[i % RECIPIENTS.length]!,
      denom: "uqor",
      amount: String(1_000_000 * (i + 1) + 7),
    }));
    const tree = withdrawalsTree(withdrawals, { rollupId, version: "v2", chainId: CHAIN_ID });
    const root = BigInt("0x" + hex(tree.root));
    cases.push({
      name: `${rollupId}-${n}`,
      input: { chain_id: CHAIN_ID, rollup_id: rollupId, withdrawals },
      expected: {
        leaves: tree.leaves.map(hex),
        root: hex(tree.root),
        root_mod_r: (root % BLS12_381_SCALAR_MODULUS).toString(16).padStart(64, "0"),
      },
    });
  }
}
const file = join(REPO_ROOT, "spec", "vectors", "withdrawals.json");
writeFileSync(file, JSON.stringify(cases, null, 2) + "\n");
console.log(`${cases.length} cases -> ${file}`);
