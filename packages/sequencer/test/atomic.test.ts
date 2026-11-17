import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { atomicCopy, atomicWrite, sweepTemp } from "../src/atomic.ts";

const dir = mkdtempSync(join(tmpdir(), "atomic-"));
const big = (n: number) => JSON.stringify({ version: n, filler: "x".repeat(8 << 20), end: n }); // 8 MB, so a kill lands mid-write

test("a write replaces the file whole and leaves no temporary file", () => {
  const f = join(dir, "a.json");
  atomicWrite(f, '{"a":1}');
  atomicWrite(f, '{"a":2}');
  assert.equal(readFileSync(f, "utf8"), '{"a":2}');
  assert.deepEqual(readdirSync(dir).filter((x) => x.startsWith(".tmp-")), []);
});

test("a copy replaces the destination whole", () => {
  const src = join(dir, "src.json"), dst = join(dir, "dst.json");
  writeFileSync(src, big(9));
  writeFileSync(dst, big(1));
  atomicCopy(src, dst);
  assert.equal(JSON.parse(readFileSync(dst, "utf8")).version, 9);
});

test("sweepTemp removes what a crash left and nothing else", () => {
  writeFileSync(join(dir, ".tmp-123-state.json"), "{trunc");
  writeFileSync(join(dir, "state.json"), '{"ok":true}');
  assert.deepEqual(sweepTemp(dir), [".tmp-123-state.json"]);
  assert.equal(existsSync(join(dir, "state.json")), true);
  assert.deepEqual(sweepTemp(join(dir, "no-such-dir")), []);
});

test("killing the writer at random moments never leaves a truncated or mixed file (30 kills)", async () => {
  const f = join(dir, "state.json");
  atomicWrite(f, big(0));
  const script = `import { atomicWrite } from ${JSON.stringify(join(import.meta.dirname, "..", "src", "atomic.ts"))};
    const big = (n) => JSON.stringify({ version: n, filler: "x".repeat(8 << 20), end: n });
    for (let n = 1; ; n++) atomicWrite(${JSON.stringify(f)}, big(n));`;
  const seen = new Set<number>();
  for (let i = 0; i < 30; i++) {
    const child = spawn(process.execPath, ["--import", "tsx", "--input-type=module", "-e", script], { stdio: "ignore" });
    await new Promise((r) => setTimeout(r, 150 + Math.floor(Math.random() * 350)));
    child.kill("SIGKILL");
    await new Promise((r) => child.once("exit", r));
    const parsed = JSON.parse(readFileSync(f, "utf8")) as { version: number; end: number }; // throws on a truncated file
    assert.equal(parsed.version, parsed.end, "the file mixes two versions");
    seen.add(parsed.version);
  }
  assert.ok(seen.size > 1, "the writer never got to replace the file, so the test proved nothing");
  assert.ok(sweepTemp(dir).length >= 0);
});

test("after the loop: the same kill test against a plain writeFileSync would have failed (control)", async () => {
  const f = join(dir, "plain.json");
  writeFileSync(f, big(0));
  const script = `import { writeFileSync } from "node:fs";
    const big = (n) => JSON.stringify({ version: n, filler: "x".repeat(8 << 20), end: n });
    for (let n = 1; ; n++) writeFileSync(${JSON.stringify(f)}, big(n));`;
  let broken = 0;
  for (let i = 0; i < 30 && !broken; i++) {
    const child = spawn(process.execPath, ["--input-type=module", "-e", script], { stdio: "ignore" });
    await new Promise((r) => setTimeout(r, 60 + Math.floor(Math.random() * 200)));
    child.kill("SIGKILL");
    await new Promise((r) => child.once("exit", r));
    try { const p = JSON.parse(readFileSync(f, "utf8")); if (p.version !== p.end) broken++; } catch { broken++; }
  }
  assert.ok(broken > 0, "a plain write was never caught half-done: the kill test is not sensitive enough to show the difference");
});

test("cleanup", () => rmSync(dir, { recursive: true, force: true }));
