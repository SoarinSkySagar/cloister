import { buildSettlementReceipt, createRdkClient, type SettlementReceipt } from "@qorechain/rdk";
import { parseReceipt, verifyReceipt, checkVerdicts, summarize, type CoSignature, type ReceiptVerdict } from "../src/verify.ts";
import { parseVerdicts } from "../src/verdict.ts";

const $ = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;
const esc = (v: unknown) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);
const client = createRdkClient({ network: "testnet", endpoints: { rest: `${location.origin}/chain`, rpc: `${location.origin}/rpc` } });
const json = (o: unknown) => JSON.stringify(o, (_k, v) => (typeof v === "bigint" ? v.toString() : v), 2);

function render(r: SettlementReceipt | undefined, v: ReceiptVerdict, problem?: string) {
  const box = $("result");
  box.hidden = false;
  if (!r) {
    box.innerHTML = `<div class="verdict bad"><div class="mark">✕</div><div><h3>Not a receipt</h3><p>${esc(problem)}</p></div></div>`;
    return;
  }
  const ok = v.valid;
  box.innerHTML = `
    <div class="verdict ${ok ? "ok" : "bad"}"><div class="mark">${ok ? "✓" : "✕"}</div>
      <div><h3>${ok ? "Valid receipt" : "Invalid receipt"}</h3>
      <p>${ok ? `${esc(r.rollupId)} batch ${esc(r.batchIndex)} matches what QoreChain holds.` : esc(v.error ?? "The chain does not agree with this receipt.")}</p></div></div>
    <div class="kv">
      <div>Rollup</div><div class="mono">${esc(r.rollupId)}</div>
      <div>Batch</div><div class="mono">${esc(r.batchIndex)}</div>
      <div>State root</div><div class="mono">${esc(r.stateRoot)}</div>
      <div>Anchor signer</div><div class="mono">${esc(r.creator)} · ${esc(r.algorithm)}</div>
      <div>Anchored on L1</div><div class="mono">height ${esc(r.mainChainHeight)} · ${esc(new Date(Number(r.anchoredAt) * 1000).toISOString())}</div>
      <div>Chain</div><div class="mono">${esc(r.chainId ?? "unspecified (v1)")}</div>
      <div>Mode</div><div class="mono">${esc(v.mode)}</div>
    </div>
    ${v.checks.length ? `<table><thead><tr><th>Check</th><th>Result</th></tr></thead><tbody>${v.checks.map((c) => `<tr><td class="mono">${esc(c.name)}</td><td><span class="pill ${c.ok ? "ok" : "bad"}">${c.ok ? "pass" : "fail"}</span> <span class="muted mono">${c.ok ? "" : esc(c.detail)}</span></td></tr>`).join("")}</tbody></table>` : ""}
    <div class="note"><b>What this proves:</b> the batch's state root was settled on QoreChain and anchored with a post-quantum ML-DSA-87 signature from the rollup creator's key, which was read from the chain, not from the receipt. <b>What it does not prove:</b> that the transactions inside the batch were correct. That is the job of the Groth16 proof that settled it.</div>`;
  box.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

function coHtml(co: CoSignature[] | undefined): string {
  if (!co) return "";
  const head = `<div class="cohead"><h3>Member watchtowers</h3><span class="muted">${esc(summarize(co))}</span></div>`;
  if (!co.length) return `<div class="co">${head}<p class="note">No member has published a verdict for this batch. The receipt above shows settlement only: it does not show that anyone with access to the sealed data checked it.</p></div>`;
  const rows = co.map(({ verdict: v, check }) => {
    const state = check.unverifiable ? `<span class="pill">could not verify</span>` : !check.valid ? `<span class="pill bad">invalid</span>` : check.result === "pass" ? `<span class="pill ok">pass</span>` : `<span class="pill bad">reports a failure</span>`;
    const failed = v.checks.filter((c) => !c.ok).map((c) => c.name);
    return `<tr><td class="mono">${esc(v.watchtower)}</td><td>${state}</td><td class="muted">${esc(v.scope === "link-only" ? "hash link only (pre-bundle batch)" : v.checks.map((c) => c.name).join(", "))}</td>
      <td class="muted mono">${esc(new Date(v.signedAt * 1000).toISOString().slice(0, 16).replace("T", " "))}</td></tr>
      ${!check.valid ? `<tr><td colspan="4" class="muted">${esc(check.problems.join("; "))}</td></tr>` : failed.length ? `<tr><td colspan="4" class="muted">failed: ${esc(failed.join(", "))}</td></tr>` : ""}`;
  }).join("");
  return `<div class="co">${head}<table><thead><tr><th>Signer</th><th>Verdict</th><th>Checked</th><th>Signed (UTC)</th></tr></thead><tbody>${rows}</tbody></table>
    <div class="note">Each verdict is an ML-DSA-87 signature by a current member of the rollup. The signer's key is read from the chain, not from the verdict, and the verdict must name the same state root and data hash the chain holds. A member can still sign something false, so this adds accountability, not certainty.</div></div>`;
}

async function loadCo(r: SettlementReceipt): Promise<CoSignature[] | undefined> {
  try {
    const res = await fetch(`verdicts/${encodeURIComponent(`${r.rollupId}-${r.batchIndex}`)}.verdicts.json`);
    if (res.status === 404) return [];
    if (!res.ok) return undefined;
    const pv = parseVerdicts(await res.text());
    return "error" in pv ? undefined : await checkVerdicts(r, pv.verdicts, client);
  } catch { return undefined; }
}

async function run(text: string) {
  const p = parseReceipt(text);
  if ("error" in p) return render(undefined, { valid: false, mode: "", checks: [] }, p.error);
  $("go").setAttribute("disabled", "");
  try {
    render(p.receipt, await verifyReceipt(p.receipt, client));
    $("result").insertAdjacentHTML("beforeend", `<div id="co-slot"><p class="note muted">Looking for member watchtower verdicts…</p></div>`);
    const co = await loadCo(p.receipt);
    const slot = document.getElementById("co-slot");
    if (slot) slot.innerHTML = co === undefined ? `<p class="note muted">Could not load verdicts for this batch.</p>` : coHtml(co);
  } finally { $("go").removeAttribute("disabled"); }
}

$("go").addEventListener("click", () => void run(($("text") as HTMLTextAreaElement).value));
$("clear").addEventListener("click", () => { ($("text") as HTMLTextAreaElement).value = ""; $("result").hidden = true; });
$("lookup").addEventListener("click", async () => {
  const id = ($("rid") as HTMLInputElement).value.trim(), n = Number(($("bn") as HTMLInputElement).value);
  $("lookup").setAttribute("disabled", "");
  try {
    const r = await buildSettlementReceipt(client, id, n);
    ($("text") as HTMLTextAreaElement).value = json(r);
    await run(json(r));
  } catch (e) { render(undefined, { valid: false, mode: "", checks: [] }, `Could not build a receipt for ${id} batch ${n}: ${(e as Error).message}`); }
  finally { $("lookup").removeAttribute("disabled"); }
});

const drop = $("drop");
drop.addEventListener("dragover", (e) => { e.preventDefault(); drop.classList.add("over"); });
drop.addEventListener("dragleave", () => drop.classList.remove("over"));
drop.addEventListener("drop", async (e) => {
  e.preventDefault(); drop.classList.remove("over");
  const f = (e as DragEvent).dataTransfer?.files[0];
  if (f) { const t = await f.text(); ($("text") as HTMLTextAreaElement).value = t; void run(t); }
});

try {
  const files = (await (await fetch("receipts.json")).json()) as string[];
  $("pubn").textContent = `${files.length} in the repo`;
  $("published").innerHTML = files.map((f) => `<button type="button" data-f="${esc(f)}">${esc(f.replace(/\.json$/, ""))}</button>`).join("");
  $("published").addEventListener("click", async (e) => {
    const b = (e.target as HTMLElement).closest("button[data-f]") as HTMLElement | null;
    if (!b) return;
    const t = await (await fetch(`receipts/${b.dataset.f}`)).text();
    ($("text") as HTMLTextAreaElement).value = t; void run(t);
  });
} catch { $("pubn").textContent = "unavailable"; }
