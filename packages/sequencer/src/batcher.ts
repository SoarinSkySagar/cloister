/**
 * The sequencer core: a mempool of verified frame txs, and one batch cycle:
 * select -> seal bundle -> prove (Go, circuits/cmd/ledger) -> post -> simulate ->
 * submit with the ML-DSA-87 anchor -> advance state -> pay withdrawals on L1.
 */
import { appendFileSync, existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { atomicCopy, atomicWrite, sweepTemp } from "./atomic.ts";
import { createHash } from "node:crypto";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { join } from "node:path";
import {
  buildExecuteWithdrawalInput, envelopeMembershipError, sealEnvelope, submitBatchMsg, withdrawalsTree,
  zkPublicInputErrors, type RdkClient, type RdkTxClient,
} from "@qorechain/rdk";
import {
  BUNDLE_PAD_MAX, CHAIN_ID, NEW_ACCOUNT, REPO_ROOT, actionsOf, decodeBundle, encodeBundle, frameTxFromHex, frameTxToHex, formatQor, newAccountKey, nextFreeIndex,
  notBeforeOf, partiesOf, payerOf, pkCommit, sighash, signatureErrors, structuralErrors, toLedgerTx, type FrameTx, type RollupState,
} from "@cloister/common";

const run = promisify(execFile);
const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");
const be32 = (h: string) => Buffer.from(h.padStart(64, "0"), "hex");

export interface SequencerConfig {
  rollupId: string;
  relayerIndex: number;   // fee recipient (spec/frame-tx.md)
  minFee: bigint;         // uqor; lower fees are refused
  maxTxs: number;         // circuit v1: 4 per batch
  proofLog: boolean;      // append tx hashes to PROOF.md
  setupDir?: string;      // override circuits/setup/<id> (tests)
  /** Sealed bundle padding: none (dev rollups so far), bucket (4 KiB, 8 KiB, ...) or fixed (128 KiB every batch, about 1.3 QOR of post fee). */
  pad?: "none" | "bucket" | "fixed";
}

/** The `encodeBundle` options for a padding mode. */
export function padOptions(mode: SequencerConfig["pad"]): { pad?: boolean; fixed?: number } {
  return mode === "bucket" ? { pad: true } : mode === "fixed" ? { fixed: BUNDLE_PAD_MAX } : {};
}

/**
 * The prover reports a tx it cannot include as "tx <k>: fee: ...", "tx <k>: window: ..." or
 * "tx <k> action <j>: auth: ..." (an unpayable fee, a tx outside its time window, a debit of an account that is
 * neither the sender nor a party, or a relayer other than the circuit's). The tx is dropped and the batch retried.
 */
export function txFailure(stderr: string): { index: number; reason: string } | undefined {
  const m = /tx (\d+)(?: action \d+)?: ((?:fee|window|auth|relayer|parties|account index|invalid|a new account)[^\n]*)/.exec(stderr);
  return m ? { index: Number(m[1]), reason: m[2]!.trim() } : undefined;
}
export const feeFailure = txFailure;

/** One saved inclusion proof (spec/inclusion.md), keyed by the tx's sighash. */
export interface SavedProof { tx_id: string; proof: InclusionProofJSON }
export interface InclusionProofJSON {
  version: number; chainId: string; rollupId: string; batchIndex: number;
  record: { sender: number; parties: number[]; moves?: { from: number }[] } & Record<string, unknown>;
  txIndex: number; txPath: string[]; logPath: string[];
}

export type TxStatus =
  | { status: "queued"; queuedAt: number }
  | { status: "included"; batch: number; account?: number; applied: boolean[]; skipped?: string[]; submitTx: string }
  | { status: "rejected"; reason: string };

/** index -> ML-DSA-87 public key, persisted next to the state (members-only data). */
export class Keystore {
  private keys = new Map<number, Uint8Array>();
  constructor(private path: string) {
    if (existsSync(path)) {
      for (const [i, k] of Object.entries(JSON.parse(readFileSync(path, "utf8")) as Record<string, string>)) {
        this.keys.set(Number(i), new Uint8Array(Buffer.from(k, "hex")));
      }
    }
  }
  get = (i: number) => this.keys.get(i);
  set(i: number, pk: Uint8Array) {
    this.keys.set(i, pk);
    atomicWrite(this.path, JSON.stringify(Object.fromEntries([...this.keys].map(([k, v]) => [k, hex(v)])), null, 1));
  }
  /** Bind known public keys to the accounts whose pk_commit they match. */
  learn(state: RollupState, publicKeys: Uint8Array[]) {
    for (const pk of publicKeys) {
      const c = pkCommit(pk);
      for (const a of state.accounts) if (a.pk_commit === c && !this.keys.has(a.index)) this.set(a.index, pk);
    }
  }
}

export class Sequencer {
  readonly setupRel: string;
  readonly setupDir: string;
  readonly keystore: Keystore;
  private mempool: { id: string; tx: FrameTx }[] = [];
  readonly statuses = new Map<string, TxStatus>();
  private busy = false;
  lastError = "";

  constructor(
    readonly cfg: SequencerConfig,
    private rdk: RdkClient,
    private tx: RdkTxClient,
    private operator: string,
  ) {
    this.setupRel = join("setup", cfg.rollupId);
    this.setupDir = cfg.setupDir ?? join(REPO_ROOT, "circuits", this.setupRel);
    sweepTemp(this.setupDir); // a crash can leave half-written temporary files; the real files are never half-written
    this.keystore = new Keystore(join(this.setupDir, "keys.json"));
  }

  state(): RollupState {
    return JSON.parse(readFileSync(join(this.setupDir, "state.json"), "utf8")) as RollupState;
  }

  queueLength = () => this.mempool.length;
  isBusy = () => this.busy;

  /** Nonces after everything already queued. */
  private pendingNonces(state: RollupState) {
    const n = new Map(state.accounts.map((a) => [a.index, BigInt(a.nonce)]));
    for (const { tx } of this.mempool) if (tx.sender !== NEW_ACCOUNT) n.set(tx.sender, tx.nonce + 1n);
    return n;
  }

  /** Validate and queue a signed tx. Returns its id (the sighash) or throws with the reason. */
  submit(tx: FrameTx): string {
    const id = hex(sighash(tx));
    if (this.statuses.has(id) && this.statuses.get(id)!.status !== "rejected") throw new Error("duplicate tx");
    const state = this.state();
    const errs = [
      ...structuralErrors(tx, { chainId: CHAIN_ID, rollupId: this.cfg.rollupId }),
      ...signatureErrors(tx, this.keystore.get),
    ];
    if (tx.maxFee < this.cfg.minFee) errs.push(`fee below the relayer minimum of ${formatQor(this.cfg.minFee)}`);
    if (tx.expiryBatch < BigInt(state.batches)) errs.push(`expired at batch ${tx.expiryBatch}`);
    if (tx.sender !== NEW_ACCOUNT) {
      const want = this.pendingNonces(state).get(tx.sender);
      if (want === undefined) errs.push(`account #${tx.sender} does not exist`);
      else if (tx.nonce !== want) errs.push(`nonce ${tx.nonce}, expected ${want}`);
    } else {
      const c = pkCommit(newAccountKey(tx) ?? new Uint8Array());
      if (state.accounts.some((a) => a.pk_commit === c)) errs.push("this key already has an account");
      if (this.mempool.some((m) => m.tx.sender === NEW_ACCOUNT && pkCommit(newAccountKey(m.tx)!) === c)) errs.push("registration already queued");
    }
    const payer = payerOf(tx);
    if (payer !== tx.sender && !state.accounts.some((a) => a.index === payer)) errs.push(`sponsor #${payer} does not exist`);
    for (const p of partiesOf(tx)) if (!state.accounts.some((a) => a.index === p)) errs.push(`party #${p} does not exist`);
    if (errs.length) throw new Error(errs.join("; "));
    this.mempool.push({ id, tx });
    this.persist();
    this.statuses.set(id, { status: "queued", queuedAt: Date.now() });
    return id;
  }

  /** Txs that may be included in the next batch: their GUARD not_before has been reached. */
  private ready(batchIndex: number) {
    return this.mempool.filter(({ tx }) => notBeforeOf(tx) <= BigInt(batchIndex));
  }

  /** One batch cycle; resolves with the batch index, or undefined if nothing was queued (or nothing is due yet). */
  async runBatch(): Promise<number | undefined> {
    if (this.busy || !this.ready(this.state().batches).length) return undefined;
    this.busy = true;
    try {
      return await this.cycle();
    } catch (e) {
      this.lastError = e instanceof Error ? e.message : String(e);
      throw e;
    } finally {
      this.busy = false;
    }
  }

  private log(what: string, ref: string) {
    console.log(`[seq] ${what} ${ref}`);
    if (this.cfg.proofLog) appendFileSync(join(REPO_ROOT, "PROOF.md"), `| ${new Date().toISOString().slice(0, 10)} | ${what} | ${ref} | testnet |\n`);
  }

  private async cycle(): Promise<number | undefined> {
    const { rollupId } = this.cfg;
    const state = this.state();
    const latest = await this.rdk.rest.getLatestBatch(rollupId).catch(() => undefined);
    const batchIndex = latest ? latest.batchIndex + 1 : 0;
    if (batchIndex !== state.batches) throw new Error(`chain is at batch ${batchIndex}, local state at ${state.batches}`);
    if (latest && latest.stateRoot.toLowerCase().padStart(64, "0") !== state.root) throw new Error("local state root differs from the chain's");

    // Select up to maxTxs, dropping expired ones; assign indexes to new accounts in order.
    let picked = this.ready(batchIndex).slice(0, this.cfg.maxTxs).filter(({ id, tx }) => {
      if (tx.expiryBatch < BigInt(batchIndex)) { this.reject(id, `expired at batch ${tx.expiryBatch}`); return false; }
      return true;
    });

    for (;;) {
      if (!picked.length) return undefined;
      const used = new Set(state.accounts.map((a) => a.index));
      const assigned = picked.map(({ tx }) => {
        if (tx.sender !== NEW_ACCOUNT) return undefined;
        const i = nextFreeIndex(used); used.add(i); return i;
      });
      const ledgerTxs = picked.map(({ tx }, i) => toLedgerTx(tx, { relayer: this.cfg.relayerIndex, senderIndex: assigned[i] }));
      const bundle = encodeBundle(batchIndex, picked.map((p) => p.tx), padOptions(this.cfg.pad));

      const rollup = await this.rdk.rest.getRollup(rollupId);
      const recipients = await Promise.all(rollup.members.map(async (member) => {
        const kem = await this.rdk.rest.getKemKey(member);
        if (!kem) throw new Error(`member ${member} has no ML-KEM key`);
        return { member, encapsulationKey: kem.publicKey };
      }));
      const envelope = sealEnvelope({ chainId: CHAIN_ID, rollupId, epoch: rollup.membersEpoch, recipients, plaintext: bundle });
      const bad = envelopeMembershipError(envelope, { membersEpoch: rollup.membersEpoch, members: recipients });
      if (bad) throw new Error(`envelope refused: ${bad}`);
      const sha = createHash("sha256").update(envelope).digest("hex");

      const outRel = join("build", `${rollupId}-b${batchIndex}`);
      const out = join(REPO_ROOT, "circuits", outRel);
      mkdirSync(out, { recursive: true });
      writeFileSync(join(out, "batch.json"), JSON.stringify({ txs: ledgerTxs }, null, 2));
      writeFileSync(join(out, "bundle.bin"), bundle);   // lets recover() relearn the keys registered in this batch
      try {
        await run("go", ["run", "./cmd/ledger", "prove", "-dir", this.setupRel, "-batch", join(outRel, "batch.json"), "-data", sha, "-out", outRel],
          { cwd: join(REPO_ROOT, "circuits"), maxBuffer: 64 << 20 });
      } catch (e) {
        // A tx whose fee its payer cannot cover is dropped, and the batch retried.
        const f = txFailure(String((e as { stderr?: string }).stderr ?? e));
        if (!f) throw e;
        this.reject(picked[f.index]!.id, f.reason);
        picked = picked.filter((_, i) => i !== f.index);
        continue;
      }
      const result = JSON.parse(readFileSync(join(out, "result.json"), "utf8")) as {
        state_root: string; withdrawals_root: string; withdrawals: { recipient: string; amount: number }[] | null;
        txs: { applied: boolean[]; skipped?: string[] }[]; tx_count: number;
        inclusion?: InclusionProofJSON[];
      };

      const withdrawals = (result.withdrawals ?? []).map((w) => ({ recipient: w.recipient, denom: "uqor", amount: String(w.amount) }));
      const tree = withdrawals.length ? withdrawalsTree(withdrawals, { rollupId, version: "v2", chainId: CHAIN_ID }) : undefined;
      if ((tree ? hex(tree.root) : "") !== result.withdrawals_root) throw new Error("RDK withdrawals root differs from the circuit's");
      const inputs = {
        prevStateRoot: batchIndex === 0 ? undefined : be32(state.root),
        stateRoot: be32(result.state_root), dataHash: Buffer.from(sha, "hex"), withdrawalsRoot: tree?.root,
      };
      const errs = zkPublicInputErrors(inputs, { dataHashBound: true });
      if (errs.length) throw new Error(`public inputs: ${errs.join("; ")}`);

      const post = await this.tx.postRollupData({ rollupId, data: envelope });
      if (post.code !== 0) throw new Error(`post failed: ${post.rawLog}`);
      const inbox = await this.rdk.rest.getInbox(rollupId);
      const posted = await this.rdk.rest.getPostedData(rollupId, inbox.headSequence);
      if (posted.dataHash.toLowerCase() !== sha) throw new Error("chain post hash differs from the envelope");
      this.log(`${rollupId} batch ${batchIndex}: sealed bundle of ${picked.length} signed frame tx(s) posted (${envelope.length} B, members only)`, `\`${post.transactionHash}\``);

      const proof = readFileSync(join(out, "proof.raw.bin"));
      await this.tx.simulate([submitBatchMsg({ sequencer: this.operator, rollupId, batchIndex, txCount: result.tx_count, ...inputs, proof })]);
      const res = await this.tx.submitBatch({ rollupId, batchIndex, txCount: result.tx_count, ...inputs, proof }, { anchor: "require" });
      if (res.code !== 0) throw new Error(`submitBatch failed (code ${res.code}): ${res.rawLog}`);
      const settled = await this.rdk.rest.getBatch(rollupId, batchIndex);
      atomicCopy(join(out, "next-state.json"), join(this.setupDir, "state.json"));
      this.log(`${rollupId} batch ${batchIndex}: sequencer service, ${picked.length} frame tx(s), ${withdrawals.length} withdrawal(s), circuit v3 proof verified on chain; status ${settled.status}`, `\`${res.transactionHash}\``);

      this.record(picked, assigned, result.txs, batchIndex, res.transactionHash);
      this.saveProofs(batchIndex, picked.map((p) => p.id), result.inclusion ?? []);

      if (tree) {
        if (settled.status !== "finalized") throw new Error("batch not finalized: withdrawals deferred");
        for (let i = 0; i < withdrawals.length; i++) {
          const w = withdrawals[i]!;
          const x = await this.tx.executeWithdrawal(buildExecuteWithdrawalInput({
            submitter: this.operator, rollupId, batchIndex, ...w, withdrawal: tree.proof(i),
          }));
          if (x.code !== 0) throw new Error(`executeWithdrawal ${i} failed: ${x.rawLog}`);
          this.log(`${rollupId} batch ${batchIndex}: withdrawal #${i} of ${formatQor(w.amount)} to ${w.recipient} paid on L1`, `\`${x.transactionHash}\``);
        }
      }
      return batchIndex;
    }
  }


  /** After a batch is accepted: remember outcomes and the keys of newly registered accounts. */
  record(picked: { id: string; tx: FrameTx }[], assigned: (number | undefined)[], results: { applied: boolean[]; skipped?: string[] }[], batchIndex: number, submitTx: string) {
    picked.forEach(({ id, tx }, i) => {
      const account = assigned[i] ?? tx.sender;
      // actionsOf builds new objects on every call, so locate the action by index, never by identity.
      const acts = actionsOf(tx);
      const k = acts.findIndex((a) => a.kind === "register_key");
      const reg = k >= 0 ? acts[k] : undefined;
      if (reg?.kind === "register_key" && results[i]?.applied[k]) this.keystore.set(account, reg.publicKey);
      this.statuses.set(id, { status: "included", batch: batchIndex, account, applied: results[i]!.applied, skipped: results[i]!.skipped, submitTx });
    });
    const done = new Set(picked.map((p) => p.id));
    this.mempool = this.mempool.filter((m) => !done.has(m.id));
    this.persist();
  }


  private proofsDir() { return join(this.setupDir, "proofs"); }

  /** Keep each included tx's inclusion proof (members-only data, like the state). Proofs are in tx slot order. */
  saveProofs(batchIndex: number, ids: string[], proofs: InclusionProofJSON[]) {
    if (proofs.length !== ids.length) throw new Error(`prover returned ${proofs.length} inclusion proofs for ${ids.length} txs`);
    mkdirSync(this.proofsDir(), { recursive: true });
    const saved: SavedProof[] = ids.map((tx_id, i) => ({ tx_id, proof: proofs[i]! }));
    atomicWrite(join(this.proofsDir(), `${batchIndex}.json`), JSON.stringify(saved, null, 1));
  }

  /**
   * The inclusion proof of a tx, only for the accounts its record names as sender, co-signer or fee payer. `callerCommit` is the pk_commit of
   * the verified caller (a signed query); a private rollup shows a record only to the accounts it names.
   */
  proofFor(txId: string, callerCommit: string): InclusionProofJSON | { error: string } {
    if (!/^[0-9a-f]{64}$/.test(txId)) return { error: "bad tx id" };
    const me = this.state().accounts.find((a) => a.pk_commit === callerCommit);
    if (!me) return { error: "no account for this key" };
    const dir = this.proofsDir();
    if (!existsSync(dir)) return { error: "no proof for that tx" };
    for (const f of readdirSync(dir)) {
      const hit = (JSON.parse(readFileSync(join(dir, f), "utf8")) as SavedProof[]).find((p) => p.tx_id === txId);
      if (!hit) continue;
      const r = hit.proof.record;
      const payer = r.moves?.[0]?.from; // the fee move debits the payer (a sponsor is named too)
      const named = r.sender === me.index || r.parties.includes(me.index) || payer === me.index;
      return named ? hit.proof : { error: "this tx does not name your account" };
    }
    return { error: "no proof for that tx" };
  }

  private mempoolFile() { return join(this.setupDir, "mempool.json"); }
  private persist() {
    atomicWrite(this.mempoolFile(), JSON.stringify(this.mempool.map((m) => frameTxToHex(m.tx))));
  }

  /** Re-queue txs that were accepted before a restart (each is re-validated against the current state). */
  restore(): { requeued: number; dropped: string[] } {
    const dropped: string[] = [];
    let requeued = 0;
    if (!existsSync(this.mempoolFile())) return { requeued, dropped };
    for (const h of JSON.parse(readFileSync(this.mempoolFile(), "utf8")) as string[]) {
      try { this.submit(frameTxFromHex(h)); requeued++; } catch (e) { dropped.push((e as Error).message); }
    }
    this.persist();
    return { requeued, dropped };
  }

  /**
   * A crash between submitBatch and the local state update leaves the chain one batch ahead.
   * If the prover's next-state for that batch matches the chain's root, adopt it and relearn the
   * keys the batch registered. Anything else is refused: never guess at state.
   */
  async recover(): Promise<string | undefined> {
    const { rollupId } = this.cfg;
    const state = this.state();
    const latest = await this.rdk.rest.getLatestBatch(rollupId).catch(() => undefined);
    const chainNext = latest ? latest.batchIndex + 1 : 0;
    if (chainNext === state.batches) return undefined;
    if (latest && chainNext === state.batches + 1) {
      const dir = join(this.setupDir, "..", "..", "build", `${rollupId}-b${state.batches}`);
      const next = join(dir, "next-state.json");
      if (existsSync(next)) {
        const adopted = JSON.parse(readFileSync(next, "utf8")) as RollupState;
        if (adopted.batches === chainNext && adopted.root === latest.stateRoot.toLowerCase().padStart(64, "0")) {
          atomicCopy(next, join(this.setupDir, "state.json"));
          const bundle = join(dir, "bundle.bin");
          if (existsSync(bundle)) {
            for (const tx of decodeBundle(new Uint8Array(readFileSync(bundle))).txs) {
              for (const a of actionsOf(tx)) {
                if (a.kind !== "register_key") continue;
                const acct = adopted.accounts.find((x) => x.pk_commit === pkCommit(a.publicKey));
                if (acct) this.keystore.set(acct.index, a.publicKey);
              }
            }
          }
          return `adopted batch ${state.batches} (chain was one ahead of local state)`;
        }
      }
    }
    throw new Error(`cannot recover: chain expects batch ${chainNext}, local state is at ${state.batches}`);
  }

  private reject(id: string, reason: string) {
    this.statuses.set(id, { status: "rejected", reason });
    this.mempool = this.mempool.filter((m) => m.id !== id);
    this.persist();
    console.log(`[seq] rejected ${id.slice(0, 12)}…: ${reason}`);
  }
}
