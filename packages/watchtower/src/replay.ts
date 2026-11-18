/**
 * Re-execution (design.md A6): a member replays every decrypted bundle, in order from genesis, through the same builder the
 * prover uses (`ledger simulate`: the circuit's witness must be satisfiable, no proof is made), and compares the result
 * with what the chain accepted. The circuit proves the state transition; it cannot prove that the transition is the
 * execution of the sealed bundle. Re-execution does:
 *
 *   - a sequencer that executed other transactions than it posted (a dropped or substituted tx, another order, another fee
 *     recipient, a skipped action that could apply) produces another state root;
 *   - the transaction digests and applied flags in the committed records are a function of the posted bundle, so a record
 *     that does not match its signed transaction changes the root too.
 *
 * It needs the batches from the first one, a setup directory's config.json, and `go`. Circuit v3 rollups only: a rollup
 * built with an older circuit has another record layout and replays to other roots.
 */
import { execFileSync } from "node:child_process";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { REPO_ROOT, nextFreeIndex, toLedgerTx, NEW_ACCOUNT, type FrameTx } from "@cloister/common";

export interface ReplayOutcome {
  /** The replayed batch could not be executed at all (the builder or the circuit refuses it). */
  refused?: string;
  stateRoot: string; txRoot: string; withdrawalsRoot: string;
  applied: boolean[][]; skipped: string[][];
}

const norm = (s: string) => s.toLowerCase().replace(/^0x/, "").padStart(64, "0");

export class Replayer {
  private dir: string;
  private bin: string;
  private next = 0;
  readonly relayer: number;
  /** Account indexes with a leaf, after the last replayed batch (a new account takes the next free one). */
  private used = new Set<number>();

  /** `setupDir` holds the rollup's config.json (the same file the sequencer proves with). */
  constructor(setupDir: string, opts: { binary?: string } = {}) {
    this.dir = mkdtempSync(join(tmpdir(), "replay-"));
    copyFileSync(join(setupDir, "config.json"), join(this.dir, "config.json"));
    const cfg = JSON.parse(readFileSync(join(setupDir, "config.json"), "utf8")) as { relayer: number; genesis: { index: number }[] };
    this.relayer = cfg.relayer;
    this.used = new Set(cfg.genesis.map((g) => g.index)); // genesis accounts exist before batch 0, so a new account never takes their index
    this.bin = opts.binary ?? join(this.dir, "ledger");
    if (!opts.binary) execFileSync("go", ["build", "-o", this.bin, "./cmd/ledger"], { cwd: join(REPO_ROOT, "circuits"), stdio: "pipe" });
  }

  close() { rmSync(this.dir, { recursive: true, force: true }); }

  /** The index of the next batch to replay. */
  get batch() { return this.next; }

  /**
   * Replay batch `batchIndex` (which must be the next one) holding `txs` in bundle order. A refused batch does not
   * advance the replay: nothing after it can be checked either.
   */
  replay(batchIndex: number, txs: FrameTx[], dataHashHex: string): ReplayOutcome {
    if (batchIndex !== this.next) throw new Error(`batches must be replayed in order: next is ${this.next}, got ${batchIndex}`);
    const used = new Set(this.used);
    const assigned = txs.map((t) => (t.sender === NEW_ACCOUNT ? (() => { const i = nextFreeIndex(used); used.add(i); return i; })() : undefined));
    const ledger = txs.map((t, i) => toLedgerTx(t, { relayer: this.relayer, senderIndex: assigned[i] }));
    const batchPath = join(this.dir, "batch.json");
    const out = join(this.dir, "out");
    rmSync(out, { recursive: true, force: true });
    writeFileSync(batchPath, JSON.stringify({ txs: ledger }));
    try {
      execFileSync(this.bin, ["simulate", "-dir", this.dir, "-batch", batchPath, "-data", norm(dataHashHex), "-out", out], { stdio: "pipe", maxBuffer: 64 << 20 });
    } catch (e) {
      const err = String((e as { stderr?: Buffer }).stderr ?? e).trim().split("\n").slice(-1)[0] ?? "refused";
      return { refused: err, stateRoot: "", txRoot: "", withdrawalsRoot: "", applied: [], skipped: [] };
    }
    const r = JSON.parse(readFileSync(join(out, "result.json"), "utf8")) as {
      state_root: string; tx_root: string; withdrawals_mod_r: string; txs: { applied: boolean[]; skipped?: string[] }[];
    };
    const nextState = JSON.parse(readFileSync(join(out, "next-state.json"), "utf8")) as { accounts: { index: number }[] };
    copyFileSync(join(out, "next-state.json"), join(this.dir, "state.json"));
    this.used = new Set(nextState.accounts.map((a) => a.index));
    this.next++;
    return {
      stateRoot: norm(r.state_root), txRoot: norm(r.tx_root), withdrawalsRoot: r.withdrawals_mod_r ? norm(r.withdrawals_mod_r) : "",
      applied: r.txs.map((t) => t.applied), skipped: r.txs.map((t) => t.skipped ?? []),
    };
  }

  /** The replayed accounts (index, pk_commit, balances, nonce) after the last replayed batch. */
  accounts(): { index: number; pk_commit: string; qor: number; usd: number; nonce: number }[] {
    const p = join(this.dir, "state.json");
    return existsSync(p) ? (JSON.parse(readFileSync(p, "utf8")) as { accounts: never[] }).accounts : [];
  }
}

/** What the re-execution check says about one batch, as a watchtower finding. */
export function reexecutionFinding(o: ReplayOutcome, chain: { state_root: string; tx_count: string }): { check: string; ok: boolean; detail: string } {
  if (o.refused) return { check: "reexecution", ok: false, detail: `the bundle cannot be executed: ${o.refused}` };
  const same = o.stateRoot === norm(chain.state_root);
  const skipped = o.skipped.flat();
  return {
    check: "reexecution", ok: same,
    detail: same
      ? `replayed from genesis: state root matches the chain${skipped.length ? `; ${skipped.length} skipped action(s): ${skipped.join("; ")}` : ""}`
      : `replayed state root ${o.stateRoot.slice(0, 16)}… differs from the chain's ${norm(chain.state_root).slice(0, 16)}…: the batch the chain accepted is not the execution of the sealed bundle`,
  };
}
