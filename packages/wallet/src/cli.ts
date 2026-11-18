/**
 * cloister-wallet: build, sign, seal and send Cloister frame transactions.
 *
 *   new <name>                             create a user (testnet mnemonic written to .env, never printed)
 *   whoami  --as <name> --id <rollup>      L1 address, pk_commit, rollup account, balances, nonce
 *   build   --as <name> --id <rollup> [--to <idx|name> --amount <x> [--asset qor|usd]]
 *           [--withdraw <qor> [--recipient qor1…]] [--register] [--sponsor <idx|name>]
 *           [--fee <qor>] [--atomic] [--expiry <batches>] --out tx.hex
 *   sign    --as <name> --in tx.hex        fill this identity's slot (sender or sponsor)
 *   inspect --in tx.hex [--id <rollup>]    decode, check structure and signatures
 *   status  --tx <id> --seq <url>          where a tx sent to the sequencer is (queued, included, rejected)
 *   send    --in tx.hex --id <rollup> [--seq <url>] [--via operator] [--envelope out.bin]
 *           with --seq (or CLOISTER_SEQUENCER_URL): hand the signed tx to the sequencer.
 *           seal to the rollup's members (ML-KEM-1024) and post. A dedicated rollup only accepts
 *           posts from its sequencer, so on cloister-dev-N pass --via operator (dev only) or
 *           --envelope to hand the sealed bytes to the relayer.
 *
 * QOR amounts are in QOR (decimals allowed), USD amounts in USD (6 decimals).
 * Account lookups: with --seq, a signed query to the sequencer returns your own account only.
 * Without it, the operator's local state view (circuits/setup/<rollup>/state.json, or --state).
 */
import { createHash } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { envelopeMembershipError, generateMnemonic, sealEnvelope } from "@qorechain/rdk";
import {
  ASSET, CHAIN_ID, NEW_ACCOUNT, REPO_ROOT, actionsOf, allIdentities, buildFrameTx, fillEnvValues, findByCommit,
  formatQor, frameTxFromHex, frameTxToHex, identity, isValidUserName, loadEnv, payerOf, sighash, signFrameTx,
  signatureErrors, structuralErrors, testnetClient, txClientFor, userEnvName, encodeFrameTx,
  signAccountQuery, type Action, type FrameTx, type Identity, type RollupState, type StateAccount,
} from "@cloister/common";

const [cmd, ...args] = process.argv.slice(2);
const flag = (n: string) => { const i = args.indexOf(n); return i === -1 ? undefined : args[i + 1]; };
const has = (n: string) => args.includes(n);
const need = (n: string) => { const v = flag(n); if (!v) throw new Error(`${n} is required`); return v; };
const rdk = testnetClient();
const env = loadEnv();

/** Decimal string -> integer units (6 decimals for both QOR and USD). */
function units(s: string): bigint {
  if (!/^\d+(\.\d{1,6})?$/.test(s)) throw new Error(`bad amount "${s}" (max 6 decimals)`);
  const [w, f = ""] = s.split(".");
  return BigInt(w!) * 1_000_000n + BigInt(f.padEnd(6, "0"));
}
const fmtUsd = (u: bigint | number) => `${(Number(u) / 1e6).toLocaleString("en-US", { maximumFractionDigits: 6 })} USD`;

const SEQ = flag("--seq") ?? env.CLOISTER_SEQUENCER_URL;

async function seqCall(path: string, init?: { method?: string; body?: unknown }): Promise<any> {
  if (!SEQ) throw new Error("no sequencer: pass --seq http://127.0.0.1:8787 or set CLOISTER_SEQUENCER_URL");
  const r = await fetch(new URL(path, SEQ), {
    method: init?.method ?? "GET", headers: { "content-type": "application/json" },
    body: init?.body === undefined ? undefined : JSON.stringify(init.body),
  });
  const j = await r.json();
  if (!r.ok) throw new Error(`sequencer: ${j.error ?? r.status}`);
  return j;
}

/** The caller's own account: from the sequencer (signed query) if configured, else the local state view. */
async function myAccount(me: Identity, rollupId: string): Promise<{ account?: StateAccount; batches: number; source: string }> {
  if (SEQ) {
    const r = await seqCall("/account", { method: "POST", body: signAccountQuery(rollupId, me.publicKey, me.secretKey) });
    return { account: r.account ?? undefined, batches: r.batches, source: "sequencer (signed query)" };
  }
  const st = loadState(rollupId);
  return { account: findByCommit(st, me.pkCommit), batches: st.batches, source: "local state view" };
}

function loadState(rollupId: string): RollupState {
  const path = flag("--state") ?? join(REPO_ROOT, "circuits", "setup", rollupId, "state.json");
  if (!existsSync(path)) throw new Error(`no state view at ${path} (pass --state)`);
  return JSON.parse(readFileSync(path, "utf8")) as RollupState;
}

/** Resolve "--to 2" or "--to watchtower" to an account index. */
async function accountIndex(ref: string, state: RollupState): Promise<number> {
  if (/^\d+$/.test(ref)) return Number(ref);
  if (SEQ) throw new Error(`with a sequencer, give account indexes (not "${ref}"): other accounts are private`);
  const id = await identity(rdk, ref, env);
  const acct = findByCommit(state, id.pkCommit);
  if (!acct) throw new Error(`${ref} has no account on this rollup yet`);
  return acct.index;
}

const readTx = (path: string) => frameTxFromHex(readFileSync(path, "utf8"));
const writeTx = (path: string, tx: FrameTx) => writeFileSync(path, frameTxToHex(tx) + "\n");

function describe(tx: FrameTx) {
  const who = (i: number) => (i === NEW_ACCOUNT ? "new account" : `#${i}`);
  console.log(`frame tx v${tx.version} ${tx.chainId}/${tx.rollupId}`);
  console.log(`  sender ${who(tx.sender)}  nonce ${tx.nonce}  expiry batch ${tx.expiryBatch}`);
  const payer = payerOf(tx);
  console.log(`  payer  ${who(payer)}${payer !== tx.sender ? " (sponsor)" : ""}  fee ${tx.feeAsset === ASSET.QOR ? formatQor(tx.maxFee) : fmtUsd(tx.maxFee)}`);
  for (const a of actionsOf(tx)) {
    const at = a.atomic ? " [atomic]" : "";
    if (a.kind === "transfer") console.log(`  transfer ${a.asset === ASSET.QOR ? formatQor(a.amount) : fmtUsd(a.amount)} -> #${a.to}${at}`);
    if (a.kind === "withdraw") console.log(`  withdraw ${formatQor(a.amount)} -> L1 ${a.recipient}${at}`);
    if (a.kind === "register_key") console.log(`  register_key ML-DSA-87 (${a.publicKey.length} B)${at}`);
  }
  console.log(`  sighash ${Buffer.from(sighash(tx)).toString("hex")}`);
}

async function keyOfFor(rollupId: string | undefined): Promise<(i: number) => Uint8Array | undefined> {
  if (!rollupId) return () => undefined;
  const state = loadState(rollupId);
  const ids = await allIdentities(rdk, env);
  return (i) => {
    const acct = state.accounts.find((a) => a.index === i);
    return acct ? ids.find((id) => id.pkCommit === acct.pk_commit)?.publicKey : undefined;
  };
}

switch (cmd) {
  case "new": {
    const name = args[0] ?? "";
    if (!isValidUserName(name)) throw new Error("name: 2-16 lowercase letters/digits, not a role name");
    const added = fillEnvValues({ [userEnvName(name)]: generateMnemonic(256) });
    if (!added.length) throw new Error(`${name} already exists`);
    const id = await identity(rdk, name, loadEnv());
    console.log(`created ${name}: ${id.address}`);
    console.log(`  pk_commit ${id.pkCommit}  (mnemonic stored in .env as ${userEnvName(name)})`);
    break;
  }
  case "whoami": {
    const me = await identity(rdk, need("--as"), env);
    console.log(`${me.name}: L1 ${me.address}  (${formatQor(await rdk.rest.getBalance(me.address, "uqor"))} on L1)`);
    console.log(`  ML-DSA-87 pk_commit ${me.pkCommit}`);
    const id = flag("--id");
    if (id) {
      const { account: a, batches, source } = await myAccount(me, id);
      console.log(a ? `  ${id} account #${a.index}: ${formatQor(BigInt(a.qor))}, ${fmtUsd(a.usd)}, nonce ${a.nonce}  (after ${batches} batches; ${source})`
        : `  no account on ${id} yet (build with --register --sponsor <idx> to onboard)`);
    }
    break;
  }
  case "build": {
    const me = await identity(rdk, need("--as"), env);
    const rollupId = need("--id");
    const state: RollupState = SEQ ? { batches: 0, root: "", accounts: [] } : loadState(rollupId);
    const mine = (await myAccount(me, rollupId)).account;
    const register = has("--register");
    if (!mine && !register) throw new Error(`${me.name} has no account on ${rollupId}: add --register (and --sponsor)`);
    if (mine && register) throw new Error(`${me.name} already has account #${mine.index}`);
    const atomic = has("--atomic");
    const actions: Action[] = [];
    if (register) actions.push({ kind: "register_key", publicKey: me.publicKey, atomic });
    if (flag("--to")) {
      const asset = (flag("--asset") ?? "qor") === "usd" ? ASSET.USD : ASSET.QOR;
      actions.push({ kind: "transfer", to: await accountIndex(need("--to"), state), asset, amount: units(need("--amount")), atomic });
    }
    if (flag("--withdraw")) {
      actions.push({ kind: "withdraw", recipient: flag("--recipient") ?? me.address, amount: units(need("--withdraw")), atomic });
    }
    if (!actions.length) throw new Error("nothing to do: give --to/--amount, --withdraw or --register");
    const sponsor = flag("--sponsor");
    const latest = await rdk.rest.getLatestBatch(rollupId).catch(() => undefined);
    const tx = buildFrameTx({
      chainId: CHAIN_ID, rollupId,
      sender: mine ? mine.index : NEW_ACCOUNT,
      nonce: BigInt(flag("--nonce") ?? mine?.nonce ?? 0),
      expiryBatch: BigInt((latest ? latest.batchIndex + 1 : 0) + Number(flag("--expiry") ?? 50)),
      feeAsset: ASSET.QOR, maxFee: units(flag("--fee") ?? "0"),
      payer: sponsor ? await accountIndex(sponsor, state) : undefined,
      actions,
    });
    const errs = structuralErrors(tx, { chainId: CHAIN_ID, rollupId });
    if (errs.length) throw new Error(`invalid tx: ${errs.join("; ")}`);
    writeTx(need("--out"), tx);
    describe(tx);
    console.log(`unsigned -> ${flag("--out")}  (${encodeFrameTx(tx).length} B); next: sign --as ${me.name}${tx.sigs.length > 1 ? ", then the sponsor signs" : ""}`);
    break;
  }
  case "sign": {
    const me = await identity(rdk, need("--as"), env);
    const path = need("--in");
    const tx = readTx(path);
    let slot: number | undefined;
    if (tx.sender === NEW_ACCOUNT) {
      const reg = actionsOf(tx).find((a) => a.kind === "register_key");
      if (reg && Buffer.from(reg.publicKey).equals(Buffer.from(me.publicKey))) slot = NEW_ACCOUNT;
    }
    if (slot === undefined) {
      const acct = (await myAccount(me, tx.rollupId)).account;
      if (acct && tx.sigs.some((s) => s.signer === acct.index)) slot = acct.index;
    }
    if (slot === undefined) throw new Error(`${me.name} is neither the sender nor the sponsor of this tx`);
    const signed = signFrameTx(tx, slot, me.secretKey);
    writeTx(path, signed);
    console.log(`${me.name} signed as ${slot === tx.sender ? "sender" : "sponsor"} (ML-DSA-87, ${signed.sigs.find((s) => s.signer === slot)!.signature.length} B) -> ${path}`);
    break;
  }
  case "inspect": {
    const tx = readTx(need("--in"));
    describe(tx);
    const s = structuralErrors(tx, { chainId: tx.chainId, rollupId: tx.rollupId });
    console.log(`  structure: ${s.length ? s.join("; ") : "ok"}`);
    const unsigned = tx.sigs.filter((x) => x.signature.every((b) => b === 0)).map((x) => x.signer);
    if (unsigned.length) console.log(`  unsigned slots: ${unsigned.map((i) => (i === NEW_ACCOUNT ? "new account" : `#${i}`)).join(", ")}`);
    else console.log(`  signatures: ${signatureErrors(tx, await keyOfFor(flag("--id") ?? tx.rollupId)).join("; ") || "ok"}`);
    break;
  }
  case "send": {
    const rollupId = need("--id");
    const tx = readTx(need("--in"));
    if (SEQ && !flag("--envelope") && !flag("--via")) {
      const r = await seqCall("/tx", { method: "POST", body: { tx: frameTxToHex(tx) } });
      console.log(`accepted by the sequencer: id ${r.id}\n  track it: pnpm --silent wallet status --seq ${SEQ} --tx ${r.id}`);
      break;
    }
    const errs = [...structuralErrors(tx, { chainId: CHAIN_ID, rollupId }), ...signatureErrors(tx, await keyOfFor(rollupId))];
    if (errs.length) throw new Error(`refusing to send: ${errs.join("; ")}`);
    const rollup = await rdk.rest.getRollup(rollupId);
    const recipients = await Promise.all(rollup.members.map(async (member) => {
      const kem = await rdk.rest.getKemKey(member);
      if (!kem) throw new Error(`member ${member} has no ML-KEM key`);
      return { member, encapsulationKey: kem.publicKey };
    }));
    const envelope = sealEnvelope({ chainId: CHAIN_ID, rollupId, epoch: rollup.membersEpoch, recipients, plaintext: encodeFrameTx(tx) });
    const bad = envelopeMembershipError(envelope, { membersEpoch: rollup.membersEpoch, members: recipients });
    if (bad) throw new Error(`envelope refused: ${bad}`);
    const sha = createHash("sha256").update(envelope).digest("hex");
    console.log(`sealed to ${recipients.length} members at epoch ${rollup.membersEpoch}: ${envelope.length} B, sha256 ${sha.slice(0, 16)}…`);
    const out = flag("--envelope");
    if (out) { writeFileSync(out, envelope); console.log(`envelope -> ${out} (hand it to the relayer)`); break; }
    // Based rollup: the relayer posts (and is paid by the tx's fee). Dedicated: only the sequencer may.
    const based = rollup.sequencing === "based";
    if (!based && flag("--via") !== "operator") throw new Error(`${rollupId} is not based: only its sequencer may post. Use --via operator (dev) or --envelope <file>`);
    const poster = based ? "relayer" : "operator";
    const { tx: client } = await txClientFor(rdk, poster);
    const res = await client.postRollupData({ rollupId, data: envelope });
    if (res.code !== 0) throw new Error(`post failed: ${res.rawLog}`);
    const inbox = await rdk.rest.getInbox(rollupId);
    console.log(`posted by ${poster}: ${res.transactionHash} (inbox seq ${inbox.headSequence})`);
    break;
  }
  case "status": {
    const r = await seqCall(`/tx/${need("--tx")}`);
    console.log(JSON.stringify(r, null, 2));
    break;
  }
  default:
    console.log("usage: cloister-wallet new|whoami|build|sign|inspect|send (see src/cli.ts)");
    process.exit(cmd ? 1 : 0);
}
