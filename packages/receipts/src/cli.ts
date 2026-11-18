/**
 *   pnpm --filter @cloister/receipts cli verify <receipt.json ...>     verify against live chain state
 *   pnpm --filter @cloister/receipts cli verify --all                  every file in receipts/
 *   pnpm --filter @cloister/receipts cli build --id cloister-dev-2 --batch 3 [--out file]
 * Exit code 1 if any receipt is invalid.
 */
import { readFileSync, readdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { createRdkClient, buildSettlementReceipt } from "@qorechain/rdk";
import { parseReceipt, verifyReceipt } from "./verify.ts";

const [cmd, ...args] = process.argv.slice(2);
const flag = (n: string) => { const i = args.indexOf(n); return i === -1 ? undefined : args[i + 1]; };
const client = createRdkClient({ network: "testnet" });
const REC = join(import.meta.dirname, "..", "..", "..", "receipts");

if (cmd === "verify") {
  const files = args.includes("--all") ? readdirSync(REC).filter((f) => f.endsWith(".json")).sort().map((f) => join(REC, f)) : args.filter((a) => !a.startsWith("--"));
  if (!files.length) throw new Error("usage: verify <receipt.json ...> | --all");
  let bad = 0;
  for (const f of files) {
    const p = parseReceipt(readFileSync(f, "utf8"));
    if ("error" in p) { console.log(`INVALID ${f}: ${p.error}`); bad++; continue; }
    const v = await verifyReceipt(p.receipt, client);
    console.log(`${v.valid ? "VALID  " : "INVALID"} ${p.receipt.rollupId} batch ${p.receipt.batchIndex}  (${v.mode})${v.valid ? "" : "  " + (v.error ?? v.checks.filter((c) => !c.ok).map((c) => c.name).join(", "))}`);
    if (!v.valid) bad++;
  }
  console.log(bad ? `${bad} invalid` : `all ${files.length} receipt(s) valid`);
  process.exit(bad ? 1 : 0);
} else if (cmd === "build") {
  const id = flag("--id"), batch = Number(flag("--batch"));
  if (!id || !Number.isInteger(batch)) throw new Error("usage: build --id <rollup> --batch <n> [--out file]");
  const r = await buildSettlementReceipt(client, id, batch);
  const out = flag("--out") ?? join(REC, `${id}-${batch}.json`);
  writeFileSync(out, JSON.stringify(r, (_k, v) => (typeof v === "bigint" ? v.toString() : v), 2) + "\n");
  console.log(`receipt -> ${out}`);
} else {
  console.log("usage: verify <file...|--all> | build --id <rollup> --batch <n>");
  process.exit(2);
}
