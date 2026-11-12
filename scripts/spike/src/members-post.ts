/**
 * Private-rollup round trip on a cloister-dev-N rollup:
 *   1. set the member set to [operator, watchtower] (if not already),
 *   2. seal a sample payload to the members with ML-KEM-1024 (RDK envelope),
 *   3. post it on chain (dedicated sequencing: the creator posts),
 *   4. check the chain's SHA-256 commitment matches our bytes,
 *   5. open it as each member, and show a non-member key cannot.
 * Dry run by default (stops after building the envelope); --send to broadcast.
 */
import { appendFileSync } from "node:fs";
import { createHash, randomBytes } from "node:crypto";
import { join } from "node:path";
import { envelopeMembershipError, kemKeypairFromSeed, openEnvelope, sealEnvelope } from "@qorechain/rdk";
import {
  CHAIN_ID, REPO_ROOT, addressFor, devRollupId, kemKeypairFor, loadEnv, testnetClient, txClientFor, type Role,
} from "@cloister/common";

const args = process.argv.slice(2);
const SEND = args.includes("--send");
const i = args.indexOf("--id");
const rollupId = i === -1 ? devRollupId(1) : args[i + 1]!;
if (!rollupId.startsWith("cloister-dev-")) throw new Error("only cloister-dev-N rollups");

const MEMBER_ROLES: Role[] = ["operator", "watchtower"];
const rdk = testnetClient();
const env = loadEnv();
const proof = (what: string, hash: string) =>
  appendFileSync(join(REPO_ROOT, "PROOF.md"), `| ${new Date().toISOString().slice(0, 10)} | ${what} | \`${hash}\` | testnet |\n`);

const members = await Promise.all(MEMBER_ROLES.map((r) => addressFor(r, env)));
if (members.some((m) => !m)) throw new Error("operator/watchtower mnemonic missing in .env");
const memberAddrs = members as string[];

let rollup = await rdk.rest.getRollup(rollupId);
console.log(`${rollupId}: privacy=${rollup.privacy} sequencing=${rollup.sequencing || "dedicated"} members=[${rollup.members.join(", ")}] epoch=${rollup.membersEpoch}`);

const { tx } = await txClientFor(rdk, "operator");
const sameMembers = rollup.members.length === memberAddrs.length && rollup.members.every((m, k) => m === memberAddrs[k]);
if (!sameMembers) {
  console.log(`set members -> [${memberAddrs.join(", ")}]`);
  if (!SEND) {
    console.log("dry run: pass --send to set members and post");
    process.exit(0);
  }
  const res = await tx.setRollupMembers({ rollupId, members: memberAddrs });
  if (res.code !== 0) throw new Error(`setRollupMembers failed (code ${res.code}): ${res.rawLog ?? ""}`);
  console.log(`  members set: ${res.transactionHash}`);
  proof(`${rollupId}: member set [operator, watchtower] (ML-KEM-1024 keys from the chain registry)`, res.transactionHash);
  rollup = await rdk.rest.getRollup(rollupId);
}

// Recipients come from the chain's KEM registry, in the rollup's member order.
const recipients = await Promise.all(
  rollup.members.map(async (member) => {
    const kem = await rdk.rest.getKemKey(member);
    if (!kem) throw new Error(`${member} has no ML-KEM key on chain`);
    return { member, encapsulationKey: kem.publicKey };
  }),
);

const plaintext = new TextEncoder().encode(
  JSON.stringify({ kind: "cloister-spike", note: "sealed to members only", at: new Date().toISOString() }),
);
const envelope = sealEnvelope({ chainId: CHAIN_ID, rollupId, epoch: rollup.membersEpoch, recipients, plaintext });
const structural = envelopeMembershipError(envelope, {
  membersEpoch: rollup.membersEpoch,
  members: recipients,
});
if (structural) throw new Error(`envelope would be refused: ${structural}`);
const sha = createHash("sha256").update(envelope).digest("hex");
console.log(`envelope: ${envelope.length} bytes (plaintext ${plaintext.length}), sha256 ${sha.slice(0, 16)}…, epoch ${rollup.membersEpoch}`);

if (!SEND) {
  console.log("dry run: pass --send to post");
  process.exit(0);
}

const before = await rdk.rest.getInbox(rollupId);
const res = await tx.postRollupData({ rollupId, data: envelope });
if (res.code !== 0) throw new Error(`postRollupData failed (code ${res.code}): ${res.rawLog ?? ""}`);
const after = await rdk.rest.getInbox(rollupId);
const seq = after.headSequence;
const posted = await rdk.rest.getPostedData(rollupId, seq);
console.log(`posted: ${res.transactionHash} (inbox ${before.headSequence} -> ${seq})`);
console.log(`chain commitment: sha256 ${posted.dataHash.slice(0, 16)}…, ${posted.size} bytes, poster ${posted.poster}`);
if (posted.dataHash.toLowerCase() !== sha) throw new Error("chain commitment does not match our envelope bytes");
proof(`${rollupId}: posted a ${envelope.length}-byte ML-KEM-1024 envelope to the members (inbox seq ${seq}); chain SHA-256 matches`, res.transactionHash);

for (const role of MEMBER_ROLES) {
  const kem = kemKeypairFor(role, env)!;
  const member = (await addressFor(role, env))!;
  const opened = openEnvelope({ envelope, chainId: CHAIN_ID, rollupId, member, decapsulationKey: kem.secretKey });
  const ok = Buffer.from(opened).equals(Buffer.from(plaintext));
  console.log(`  open as ${role.padEnd(10)} ${ok ? "OK, plaintext matches" : "MISMATCH"}`);
  if (!ok) throw new Error(`${role} opened different bytes`);
}
try {
  const outsider = kemKeypairFromSeed(randomBytes(64));
  openEnvelope({ envelope, chainId: CHAIN_ID, rollupId, member: memberAddrs[0]!, decapsulationKey: outsider.secretKey });
  throw new Error("a non-member key opened the envelope");
} catch (e) {
  if (e instanceof Error && e.message === "a non-member key opened the envelope") throw e;
  console.log("  open with a non-member key: refused (as expected)");
}
