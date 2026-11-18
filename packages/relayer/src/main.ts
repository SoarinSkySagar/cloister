/**
 *   pnpm relayer --id cloister-dev-2 [--port 8788] [--upstream http://127.0.0.1:8787] [--min-fee 0.01] [--rate 30]
 *
 *   POST /tx      { tx: <hex FrameTx> }  -> { id } or 400 { error }
 *   GET  /tx/<id>                        -> the sequencer's status for the tx
 *   POST /account  (signed query)        -> passed through to the sequencer, which checks the signature
 *   GET  /info                           -> rollup, fee floor, counters
 */
import { createServer } from "node:http";
import { CHAIN_ID } from "@cloister/common";
import { Relayer } from "./relayer.ts";

const args = process.argv.slice(2);
const flag = (n: string) => { const i = args.indexOf(n); return i === -1 ? undefined : args[i + 1]; };
const rollupId = flag("--id") ?? "";
if (!/^cloister(-dev-\d+)?$/.test(rollupId)) throw new Error("--id cloister or cloister-dev-N is required");
const port = Number(flag("--port") ?? 8788);
const relayer = new Relayer({
  chainId: CHAIN_ID, rollupId, upstream: flag("--upstream") ?? "http://127.0.0.1:8787",
  minFee: BigInt(Math.round(Number(flag("--min-fee") ?? "0.01") * 1e6)),
  maxTxBytes: 32_000, ratePerMinute: Number(flag("--rate") ?? 30),
});

const send = (res: import("node:http").ServerResponse, code: number, obj: unknown) => {
  res.writeHead(code, { "content-type": "application/json", "access-control-allow-origin": "*" });
  res.end(JSON.stringify(obj, (_k, v) => (typeof v === "bigint" ? v.toString() : v)));
};

createServer(async (req, res) => {
  try {
    const url = new URL(req.url ?? "/", "http://x");
    if (req.method === "OPTIONS") { res.writeHead(204, { "access-control-allow-origin": "*", "access-control-allow-headers": "content-type" }); return res.end(); }
    if (req.method === "POST" && url.pathname === "/tx") {
      const chunks: Buffer[] = []; let n = 0;
      for await (const c of req) { n += (c as Buffer).length; if (n > 128_000) return send(res, 413, { error: "body too large" }); chunks.push(c as Buffer); }
      const { tx } = JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}");
      try { return send(res, 200, await relayer.relay(tx, req.socket.remoteAddress ?? "anon")); }
      catch (e) { return send(res, 400, { error: (e as Error).message }); }
    }
    if (req.method === "POST" && url.pathname === "/account") {
      // Signed account query: passed through untouched, the sequencer verifies the signature.
      const chunks: Buffer[] = []; let n = 0;
      for await (const c of req) { n += (c as Buffer).length; if (n > 16_000) return send(res, 413, { error: "body too large" }); chunks.push(c as Buffer); }
      const r = await fetch(`${relayer.cfg.upstream}/account`, { method: "POST", headers: { "content-type": "application/json" }, body: Buffer.concat(chunks) });
      return send(res, r.status, await r.json());
    }
    if (req.method === "GET" && url.pathname.startsWith("/tx/")) return send(res, 200, await relayer.status(url.pathname.slice(4)));
    if (req.method === "GET" && url.pathname === "/info") return send(res, 200, { rollup_id: rollupId, min_fee: relayer.cfg.minFee, stats: relayer.stats });
    send(res, 404, { error: "not found" });
  } catch (e) { send(res, 500, { error: (e as Error).message }); }
}).listen(port, "127.0.0.1", () => console.log(`[relayer] ${rollupId} on 127.0.0.1:${port} -> ${relayer.cfg.upstream}`));
