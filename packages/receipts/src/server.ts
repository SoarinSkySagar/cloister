/**
 *   pnpm --filter @cloister/receipts start [port]      (default 8791, 127.0.0.1)
 * Serves the verifier page, the published receipts (repo receipts/) and a read-only
 * same-origin proxy to the chain, because the testnet REST/RPC send no CORS headers.
 * The proxy only forwards GET, only /qorechain/* and /cosmos/* on REST and /status on RPC.
 */
import { createServer } from "node:http";
import { readFile, readdir } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const here = fileURLToPath(new URL(".", import.meta.url));
const WEB = join(here, "..", "web");
const RECEIPTS = join(here, "..", "..", "..", "receipts");
const REST = "https://api-testnet.qore.host";
const RPC = "https://rpc-testnet.qore.host";
const port = Number(process.argv[2] ?? 8791);
import { allowedChainPath, allowedRpcPath } from "./proxy.ts";
const TYPES: Record<string, string> = { ".html": "text/html", ".js": "text/javascript", ".css": "text/css", ".json": "application/json" };

createServer(async (req, res) => {
  const send = (code: number, body: string | Buffer, type = "application/json") => { res.writeHead(code, { "content-type": type, "cache-control": "no-store" }); res.end(body); };
  try {
    if (req.method !== "GET") return send(405, JSON.stringify({ error: "GET only" }));
    const url = new URL(req.url ?? "/", "http://x");
    const p = url.pathname;
    if (p.startsWith("/chain/") || p.startsWith("/rpc/")) {
      const rest = p.startsWith("/chain/");
      const path = p.slice(rest ? 6 : 4);
      if (rest ? !allowedChainPath(path) : !allowedRpcPath(path)) return send(403, JSON.stringify({ error: "path not allowed" }));
      const r = await fetch(`${rest ? REST : RPC}${path}${url.search}`);
      return send(r.status, Buffer.from(await r.arrayBuffer()), r.headers.get("content-type") ?? "application/json");
    }
    if (p === "/receipts.json") {
      const files = (await readdir(RECEIPTS)).filter((f) => /^[a-z0-9-]+-\d+\.json$/.test(f)).sort();
      return send(200, JSON.stringify(files));
    }
    if (p.startsWith("/verdicts/")) {
      const f = p.slice(10);
      if (!/^[a-z0-9-]+-\d+\.verdicts\.json$/.test(f)) return send(404, JSON.stringify({ error: "not found" }));
      try { return send(200, await readFile(join(RECEIPTS, f))); } catch { return send(404, JSON.stringify({ error: "no verdicts" })); }
    }
    if (p.startsWith("/receipts/")) {
      const f = p.slice(10);
      if (!/^[a-z0-9-]+-\d+\.json$/.test(f)) return send(404, JSON.stringify({ error: "not found" }));
      return send(200, await readFile(join(RECEIPTS, f)));
    }
    const file = p === "/" ? "index.html" : p.slice(1);
    if (!["index.html", "app.js", "style.css"].includes(file)) return send(404, JSON.stringify({ error: "not found" }));
    return send(200, await readFile(join(WEB, file)), TYPES[file.slice(file.lastIndexOf("."))] ?? "text/plain");
  } catch (e) { send(500, JSON.stringify({ error: (e as Error).message })); }
}).listen(port, "127.0.0.1", () => console.log(`receipt verifier on http://127.0.0.1:${port}`));
