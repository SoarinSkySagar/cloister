/**
 * Crash-safe file writes. The sequencer's state files (`state.json`, `keys.json`, `mempool.json`, saved proofs) must
 * never be left half-written by a crash or a power cut: a truncated `state.json` loses the rollup's local state and
 * the next start fails to parse it. A write goes to a temporary file in the same directory, is flushed to disk, and
 * is renamed over the target; a rename is atomic, so a reader (or the next start) sees the old file or the new one,
 * never a mixture. Stale temporary files from an earlier crash are harmless and removed by `sweepTemp`.
 */
import { closeSync, copyFileSync, fsyncSync, openSync, readdirSync, renameSync, rmSync, writeSync } from "node:fs";
import { dirname, basename, join } from "node:path";

const TMP = ".tmp-";

function flushDir(dir: string) {
  try { const fd = openSync(dir, "r"); try { fsyncSync(fd); } finally { closeSync(fd); } } catch { /* a platform that cannot fsync a directory */ }
}

export function atomicWrite(path: string, data: string | Uint8Array): void {
  const tmp = join(dirname(path), `${TMP}${process.pid}-${basename(path)}`);
  const fd = openSync(tmp, "w");
  try {
    const buf = typeof data === "string" ? Buffer.from(data) : data;
    let off = 0;
    while (off < buf.length) off += writeSync(fd, buf, off, Math.min(buf.length - off, 1 << 20));
    fsyncSync(fd);
  } catch (e) {
    closeSync(fd);
    rmSync(tmp, { force: true });
    throw e;
  }
  closeSync(fd);
  renameSync(tmp, path);
  flushDir(dirname(path));
}

/** Copy `src` over `dst` atomically. */
export function atomicCopy(src: string, dst: string): void {
  const tmp = join(dirname(dst), `${TMP}${process.pid}-${basename(dst)}`);
  copyFileSync(src, tmp);
  const fd = openSync(tmp, "r+");
  try { fsyncSync(fd); } finally { closeSync(fd); }
  renameSync(tmp, dst);
  flushDir(dirname(dst));
}

/** Remove temporary files an earlier crash left in `dir`. */
export function sweepTemp(dir: string): string[] {
  const gone: string[] = [];
  try {
    for (const f of readdirSync(dir)) if (f.startsWith(TMP)) { rmSync(join(dir, f), { force: true }); gone.push(f); }
  } catch { /* no such directory yet */ }
  return gone;
}
