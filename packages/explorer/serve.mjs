// Static server for the explorer. Data comes from: pnpm watchtower --id <rollup> --explorer <abs path>/packages/explorer/data.json
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { extname, join } from "node:path";
import { fileURLToPath } from "node:url";
const root = fileURLToPath(new URL(".", import.meta.url));
const port = Number(process.argv[2] ?? 8790);
const types = { ".html": "text/html", ".js": "text/javascript", ".css": "text/css", ".json": "application/json", ".svg": "image/svg+xml" };
createServer(async (req, res) => {
  const p = new URL(req.url, "http://x").pathname;
  const file = p === "/" ? "index.html" : p.slice(1);
  if (file.includes("..") || !["index.html", "app.js", "style.css", "data.json"].includes(file)) { res.writeHead(404); return res.end("not found"); }
  try { res.writeHead(200, { "content-type": types[extname(file)] ?? "text/plain", "cache-control": "no-store" }); res.end(await readFile(join(root, file))); }
  catch { res.writeHead(404); res.end("not found"); }
}).listen(port, "127.0.0.1", () => console.log(`explorer on http://127.0.0.1:${port}`));
