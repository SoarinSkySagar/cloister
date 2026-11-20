/**
 *   pnpm --filter @cloister/receipts cli verify <receipt.json ...>     verify against live chain state
 *   pnpm --filter @cloister/receipts cli verify --all                  every file in receipts/
 *   pnpm --filter @cloister/receipts cli verify-proof <inclusion-proof.json ...>   a transaction was executed in its batch
 *   pnpm --filter @cloister/receipts cli build --id cloister-dev-2 --batch 3 [--out file]
 * Exit code 1 if any receipt is invalid.
 */
import { readFileSync, readdirSync, writeFileSync } from "node:fs";
import { isAbsolute, join } from "node:path";
import { createRdkClient, buildSettlementReceipt } from "@qorechain/rdk";
import { parseReceipt, verifyReceipt, checkVerdicts, summarize } from "./verify.ts";
import { parseVerdicts } from "./verdict.ts";
import { parseInclusion, verifyInclusion } from "./inclusion.ts";
import { existsSync } from "node:fs";

const [cmd, ...args] = process.argv.slice(2);
const flag = (n: string) => { const i = args.indexOf(n); return i === -1 ? undefined : args[i + 1]; };
const client = createRdkClient({ network: "testnet" });
const REC = join(import.meta.dirname, "..", "..", "..", "receipts");
/** `pnpm --filter` runs here, not where you typed the command: resolve file arguments against the latter. */
const here = (f: string) => (isAbsolute(f) ? f : join(process.env.INIT_CWD ?? process.cwd(), f));

if (cmd === "verify") {
  const files = args.includes("--all") ? readdirSync(REC).filter((f) => f.endsWith(".json") && !f.endsWith(".verdicts.json")).sort().map((f) => join(REC, f)) : args.filter((a) => !a.startsWith("--")).map(here);
  if (!files.length) throw new Error("usage: verify <receipt.json ...> | --all");
  let bad = 0;
  for (const f of files) {
    const p = parseReceipt(readFileSync(f, "utf8"));
    if ("error" in p) { console.log(`INVALID ${f}: ${p.error}`); bad++; continue; }
    const v = await verifyReceipt(p.receipt, client);
    console.log(`${v.valid ? "VALID  " : "INVALID"} ${p.receipt.rollupId} batch ${p.receipt.batchIndex}  (${v.mode})${v.valid ? "" : "  " + (v.error ?? v.checks.filter((c) => !c.ok).map((c) => c.name).join(", "))}`);
    if (!v.valid) bad++;
    const vf = f.replace(/\.json$/, ".verdicts.json");
    if (existsSync(vf)) {
      const pv = parseVerdicts(readFileSync(vf, "utf8"));
      if ("error" in pv) { console.log(`         verdicts: ${pv.error}`); bad++; continue; }
      const co = await checkVerdicts(p.receipt, pv.verdicts, client);
      console.log(`         ${summarize(co)}`);
      for (const c of co) {
        if (c.check.unverifiable) { console.log(`         COULD NOT VERIFY verdict by ${c.verdict.watchtower}: ${c.check.problems.join("; ")}`); bad++; }
        else if (!c.check.valid) { console.log(`         INVALID verdict by ${c.verdict.watchtower}: ${c.check.problems.join("; ")}`); bad++; }
        else if (c.check.result === "fail") { console.log(`         WARNING ${c.verdict.watchtower} reports failed checks: ${c.verdict.checks.filter((x) => !x.ok).map((x) => x.name).join(", ")}`); bad++; }
      }
    } else console.log("         no member watchtower verdict published");
  }
  console.log(bad ? `${bad} invalid` : `all ${files.length} receipt(s) valid`);
  process.exit(bad ? 1 : 0);
} else if (cmd === "verify-proof") {
  const files = args.filter((a) => !a.startsWith("--")).map(here);
  if (!files.length) throw new Error("usage: verify-proof <inclusion-proof.json ...>");
  let bad = 0;
  for (const f of files) {
    const pi = parseInclusion(readFileSync(f, "utf8"));
    if ("error" in pi) { console.log(`INVALID ${f}: ${pi.error}`); bad++; continue; }
    const v = await verifyInclusion(pi.proof, client);
    const r = pi.proof.record;
    console.log(`${v.valid ? "VALID  " : v.unverifiable ? "UNKNOWN" : "INVALID"} ${pi.proof.rollupId} batch ${pi.proof.batchIndex}, slot ${pi.proof.txIndex}: sender #${r.sender}` +
      `${r.parties.length ? `, co-signers ${r.parties.map((x) => `#${x}`).join(", ")}` : ""}${v.valid ? "" : "  " + v.problems.join("; ")}`);
    if (!v.valid) bad++;
  }
  console.log(bad ? `${bad} not valid` : `all ${files.length} proof(s) reach the chain's state root`);
  process.exit(bad ? 1 : 0);
} else if (cmd === "build") {
  const id = flag("--id"), batch = Number(flag("--batch"));
  if (!id || !Number.isInteger(batch)) throw new Error("usage: build --id <rollup> --batch <n> [--out file]");
  const r = await buildSettlementReceipt(client, id, batch);
  const out = flag("--out") ?? join(REC, `${id}-${batch}.json`);
  writeFileSync(out, JSON.stringify(r, (_k, v) => (typeof v === "bigint" ? v.toString() : v), 2) + "\n");
  console.log(`receipt -> ${out}`);
} else {
  console.log("usage: verify <file...|--all> | verify-proof <file...> | build --id <rollup> --batch <n>");
  process.exit(2);
}
