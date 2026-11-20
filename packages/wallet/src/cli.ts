/**
 * cloister-wallet: build, sign, seal and send Cloister frame transactions.
 *
 *   new <name>                             create a user (testnet mnemonic written to .env, never printed)
 *   whoami  --as <name> --id <rollup>      L1 address, pk_commit, rollup account, balances, nonce
 *   build   --as <name> --id <rollup> [--to <idx|name> --amount <x> [--asset qor|usd]]
 *           [--withdraw <qor> [--recipient qor1…]] [--register] [--sponsor <idx|name>]
 *           [--fee <qor>] [--atomic] [--expiry <batches>] [--not-before <batch>] --out tx.hex
 *           multi-party: [--party <idx|name>]… co-signers; [--leg <from>:<to>:<amount>[:qor|usd]]… a transfer
 *           debiting a party or yourself; [--withdraw-from <party>:<qor>[:<qor1… recipient>]]…
 *   sign    --as <name> --in tx.hex        fill this identity's slot (sender, party or sponsor)
 *   inspect --in tx.hex [--id <rollup>]    decode, check structure and signatures
 *   status  --tx <id> --seq <url>          where a tx sent to the sequencer is (queued, included, rejected)
 *   proof   --as <name> --tx <id> --seq <url> [--out proof.json]
 *           the inclusion proof of a tx you sent or co-signed (spec/inclusion.md); a signed query, so only its parties get it
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
  signAccountQuery, notBeforeOf, partiesOf, type Action, type FrameTx, type Identity, type RollupState, type StateAccount,
} from "@cloister/common";

const [cmd, ...args] = process.argv.slice(2);
const flag = (n: string) => { const i = args.indexOf(n); return i === -1 ? undefined : args[i + 1]; };
const has = (n: string) => args.includes(n);
/** Every value of a repeatable flag: --party a --party b. */
const flags = (n: string) => args.flatMap((a, i) => (a === n && args[i + 1] !== undefined ? [args[i + 1]!] : []));
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
  const parties = partiesOf(tx);
  if (parties.length) console.log(`  co-signers ${parties.map((p) => `#${p}`).join(", ")}`);
  if (notBeforeOf(tx) > 0n) console.log(`  not valid before batch ${notBeforeOf(tx)}`);
  for (const a of actionsOf(tx)) {
    const at = a.atomic ? " [atomic]" : "";
    const amt = (asset: number, v: bigint) => (asset === ASSET.QOR ? formatQor(v) : fmtUsd(v));
    if (a.kind === "transfer") console.log(`  transfer ${amt(a.asset, a.amount)} -> #${a.to}${at}`);
    if (a.kind === "transfer_from") console.log(`  transfer ${amt(a.asset, a.amount)} from #${a.from} -> #${a.to}${at}`);
    if (a.kind === "withdraw_from") console.log(`  withdraw ${formatQor(a.amount)} from #${a.from} -> L1 ${a.recipient}${at}`);
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

