/**
 * cloister-sequencer: HTTP API + batch loop for one rollup.
 *
 *   pnpm sequencer --id cloister-dev-5 [--port 8787] [--interval 30] [--min-fee 0.01] [--pad none|bucket|fixed] [--proof-log]
 *   (the relayer account is the circuit's: read from circuits/setup/<id>/config.json)
 *
 * API (JSON):
 *   POST /tx            { tx: <hex FrameTx> }        -> { id } (the sighash) or 400 { error }
 *   GET  /tx/<id>                                   -> queued | included (batch, account, applied) | rejected
 *   POST /account       AccountQuery (signed)        -> the caller's own account only (private rollup)
 *   POST /proof         { query (signed), tx }       -> the inclusion proof of a tx the caller sent or co-signed
 *   GET  /status                                    -> batches, queue length, busy, last error (no balances)
 *   POST /batch                                     -> run a batch now (localhost only)
 *
 * It listens on 127.0.0.1 only. A public deployment would sit behind the relayer.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import {
  REPO_ROOT, addressFor, allIdentities, frameTxFromHex, loadEnv, testnetClient, txClientFor, verifyAccountQuery,
  type AccountQuery,
} from "@cloister/common";
import { Sequencer } from "./batcher.ts";

const args = process.argv.slice(2);
const flag = (n: string) => { const i = args.indexOf(n); return i === -1 ? undefined : args[i + 1]; };
const rollupId = flag("--id") ?? "";
if (!/^cloister(-dev-\d+)?$/.test(rollupId)) throw new Error("--id cloister or cloister-dev-N is required");
const port = Number(flag("--port") ?? 8787);
const intervalSec = Number(flag("--interval") ?? 30);
const padMode = (flag("--pad") ?? "bucket") as "none" | "bucket" | "fixed";
if (!["none", "bucket", "fixed"].includes(padMode)) throw new Error("--pad is none, bucket or fixed");
const minFee = BigInt(Math.round(Number(flag("--min-fee") ?? "0.01") * 1e6));

// The fee recipient is a constant of the circuit, so the config is the one source of truth for it.
const setupConfig = JSON.parse(readFileSync(join(REPO_ROOT, "circuits", "setup", rollupId, "config.json"), "utf8")) as { relayer?: number };
if (setupConfig.relayer === undefined) throw new Error(`circuits/setup/${rollupId}/config.json has no "relayer": this setup is from an older circuit`);
if (flag("--relayer") !== undefined && Number(flag("--relayer")) !== setupConfig.relayer) {
  throw new Error(`--relayer ${flag("--relayer")} differs from the circuit's relayer account ${setupConfig.relayer}`);
}

const rdk = testnetClient();
const env = loadEnv();
const { tx } = await txClientFor(rdk, "operator");
const operator = (await addressFor("operator", env))!;
const seq = new Sequencer(
  { rollupId, relayerIndex: setupConfig.relayer, minFee, maxTxs: 4, proofLog: args.includes("--proof-log"), pad: padMode },
  rdk, tx, operator,
);
// Crash recovery, then re-queue what was accepted before the restart.
const recovered = await seq.recover();
if (recovered) console.log(`[seq] recovered: ${recovered}`);
const restored = seq.restore();
if (restored.requeued || restored.dropped.length) console.log(`[seq] mempool: ${restored.requeued} re-queued, ${restored.dropped.length} dropped${restored.dropped.length ? " (" + restored.dropped.join("; ") + ")" : ""}`);
// Keys of the configured identities whose accounts exist (genesis accounts, earlier registrations).
seq.keystore.learn(seq.state(), (await allIdentities(rdk, env)).map((i) => i.publicKey));

async function body(req: IncomingMessage): Promise<any> {
  const chunks: Buffer[] = [];
  let n = 0;
  for await (const c of req) { n += (c as Buffer).length; if (n > 1 << 20) throw new Error("body too large"); chunks.push(c as Buffer); }
  return JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}");
}
const send = (res: ServerResponse, code: number, obj: unknown) => {
  res.writeHead(code, { "content-type": "application/json" });
  res.end(JSON.stringify(obj, (_k, v) => (typeof v === "bigint" ? v.toString() : v)));
};

createServer(async (req, res) => {
  try {
    const url = new URL(req.url ?? "/", "http://x");
    if (req.method === "POST" && url.pathname === "/tx") {
      const { tx: hex } = await body(req);
      try { send(res, 200, { id: seq.submit(frameTxFromHex(String(hex))) }); }
      catch (e) { send(res, 400, { error: (e as Error).message }); }
      if (seq.queueLength() >= 4) void seq.runBatch().catch((e) => console.error("[seq] batch failed:", e.message));
      return;
    }
    if (req.method === "GET" && url.pathname.startsWith("/tx/")) {
      const s = seq.statuses.get(url.pathname.slice(4));
      return s ? send(res, 200, s) : send(res, 404, { error: "unknown tx" });
    }
    if (req.method === "POST" && url.pathname === "/account") {
      const v = verifyAccountQuery((await body(req)) as AccountQuery, rollupId);
      if ("error" in v) return send(res, 401, v);
      const state = seq.state();
      const a = state.accounts.find((x) => x.pk_commit === v.pkCommit);
      return send(res, 200, { batches: state.batches, account: a ?? null });
    }
    if (req.method === "POST" && url.pathname === "/proof") {
      // { query: <signed AccountQuery>, tx: <tx id> }: the inclusion proof of a tx the caller sent or co-signed
      const { query, tx: id } = (await body(req)) as { query: AccountQuery; tx: string };
      const v = verifyAccountQuery(query, rollupId);
      if ("error" in v) return send(res, 401, v);
      const p = seq.proofFor(String(id), v.pkCommit);
      return send(res, "error" in p ? 404 : 200, p);
    }
    if (req.method === "GET" && url.pathname === "/status") {
      return send(res, 200, { rollup_id: rollupId, batches: seq.state().batches, queued: seq.queueLength(), busy: seq.isBusy(), last_error: seq.lastError });
    }
    if (req.method === "POST" && url.pathname === "/batch") {
      const b = await seq.runBatch();
      return send(res, 200, { batch: b ?? null });
    }
    send(res, 404, { error: "not found" });
  } catch (e) {
    send(res, 500, { error: (e as Error).message });
  }
}).listen(port, "127.0.0.1", () => console.log(`[seq] ${rollupId}: listening on 127.0.0.1:${port}, batches every ${intervalSec}s when txs are queued`));

setInterval(() => { void seq.runBatch().catch((e) => console.error("[seq] batch failed:", e.message)); }, intervalSec * 1000);
