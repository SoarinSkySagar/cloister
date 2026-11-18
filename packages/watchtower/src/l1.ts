/** Fetch the bytes of a posted-data entry from the L1 tx that posted it. */
import { createHash } from "node:crypto";
const RPC_URL = "https://rpc-testnet.qore.host";

function varint(b: Uint8Array, i: number): [number, number] {
  let v = 0, shift = 0;
  for (;;) { const c = b[i++]!; v += (c & 0x7f) * 2 ** shift; if (!(c & 0x80)) return [v, i]; shift += 7; if (shift > 49) throw new Error("varint"); }
}

/** Walk protobuf fields recursively, return the length-delimited field of `size` bytes whose SHA-256 is `sha`. */
export function findBlob(buf: Uint8Array, size: number, sha: string, depth = 0): Uint8Array | undefined {
  if (depth > 6) return undefined;
  let i = 0;
  while (i < buf.length) {
    let tag: number;
    try { [tag, i] = varint(buf, i); } catch { return undefined; }
    const wire = tag & 7;
    if (wire === 0) { try { [, i] = varint(buf, i); } catch { return undefined; } }
    else if (wire === 1) i += 8;
    else if (wire === 5) i += 4;
    else if (wire === 2) {
      let len: number;
      try { [len, i] = varint(buf, i); } catch { return undefined; }
      if (i + len > buf.length) return undefined;
      const f = buf.subarray(i, i + len);
      if (len === size && createHash("sha256").update(f).digest("hex") === sha) return f;
      const inner = findBlob(f, size, sha, depth + 1);
      if (inner) return inner;
      i += len;
    } else return undefined;
  }
  return undefined;
}

export async function postedBytes(height: number, size: number, sha: string): Promise<Uint8Array> {
  let page = 1;
  for (;;) {
    const r = (await (await fetch(`${RPC_URL}/tx_search?query=%22tx.height=${height}%22&per_page=50&page=${page}`)).json()) as
      { result?: { txs: { tx: string }[]; total_count: string } };
    const txs = r.result?.txs ?? [];
    for (const t of txs) { const f = findBlob(Buffer.from(t.tx, "base64"), size, sha); if (f) return f; }
    if (page * 50 >= Number(r.result?.total_count ?? 0) || !txs.length) throw new Error(`no tx at height ${height} carries ${size} bytes with sha256 ${sha.slice(0, 12)}…`);
    page++;
  }
}
