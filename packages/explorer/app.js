// Cloister explorer. Reads data.json (written by the watchtower) and renders hash-routed pages.
const $ = (s) => document.querySelector(s);
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const short = (h, n = 10) => (h && h.length > n * 2 + 1 ? `${h.slice(0, n)}…${h.slice(-6)}` : h ?? "");
const num = (n) => Number(n).toLocaleString("en-US");
const ASSETS = ["QOR", "USD"];
const amt = (u, a = 0) => `${(Number(u) / 1e6).toLocaleString("en-US", { maximumFractionDigits: 6 })} ${ASSETS[a] ?? "?"}`;
const KIND = { 1: "transfer", 2: "withdraw", 3: "register_key", 0: "—" };
const PAGE = 20;

let D;
const camel = (o) => Object.fromEntries(Object.entries(o).map(([k, v]) => [k.replace(/_([a-z])/g, (_, c) => c.toUpperCase()), v]));
const nameOf = (i) => { const a = D.accounts.find((x) => x.index === i); return a?.name ? `${a.name} #${i}` : `#${i}`; };
const acct = (i) => (i === "new" ? `<span class="chip info">new account</span>` : `<a href="#/account/${i}">${esc(nameOf(Number(i)))}</a>`);
const hashLink = (h, kind) => `<a class="mono" href="#/${kind}/${h}">${esc(short(h))}</a>`;
const copy = (t) => `<button class="copy" data-copy="${esc(t)}" title="Copy">⧉</button>`;
const chip = (t, c = "") => `<span class="chip ${c}">${esc(t)}</span>`;
const statusChip = (s) => chip(s, s === "finalized" ? "ok" : "warn");

function load() {
  const all = D.batches.flatMap((b) => b.txs.map((t, i) => ({ ...t, batch: Number(b.batch_index), pos: i })));
  D.txs = all.reverse();
  D.byId = new Map(all.map((t) => [t.id, t]));
  D.withdrawals = all.flatMap((t) => t.actions.filter((a) => a.kind === "withdraw").map((a) => ({ ...a, sender: t.sender, batch: t.batch, tx: t.id }))).reverse();
  D.batchList = [...D.batches].reverse();
}

const table = (cols, rows, empty = "Nothing here yet.") => rows.length
  ? `<div class="scroll"><table><thead><tr>${cols.map((c) => `<th class="${c.r ? "r" : ""}">${esc(c.h)}</th>`).join("")}</tr></thead><tbody>${rows.map((r) => `<tr>${r.map((c, i) => `<td class="${cols[i].r ? "r" : ""}">${c}</td>`).join("")}</tr>`).join("")}</tbody></table></div>`
  : `<div class="empty">${empty}</div>`;
const panel = (title, body, right = "") => `<section class="panel"><div class="hd"><h2>${title}</h2><div>${right}</div></div>${body}</section>`;
const kv = (rows) => `<div class="kv">${rows.map(([k, v]) => `<div>${esc(k)}</div><div>${v}</div>`).join("")}</div>`;

const batchRows = (list) => list.map((b) => [
  `<a href="#/batch/${b.batch_index}">${b.batch_index}</a>`, statusChip(b.status), num(b.tx_count),
  `<span class="mono">${esc(short(b.state_root))}</span>`,
  Number(b.withdrawals_root.replace(/0/g, "").length) ? chip("yes", "acc") : chip("none"),
  b.ok ? chip("verified", "ok") : chip("check failed", "bad"),
]);
const batchCols = [{ h: "Batch" }, { h: "Status" }, { h: "Txs", r: 1 }, { h: "State root" }, { h: "Withdrawals" }, { h: "Watchtower" }];

const txSummary = (t) => t.actions.map((a) =>
  a.kind === "transfer" ? `send ${amt(a.amount, a.asset)} → ${nameOf(a.to)}`
  : a.kind === "withdraw" ? `withdraw ${amt(a.amount)} → ${short(a.recipient, 8)}`
  : `register key`).join("; ");
const txRows = (list) => list.map((t) => [
  hashLink(t.id, "tx"), `<a href="#/batch/${t.batch}">${t.batch}</a>`, acct(t.sender), esc(txSummary(t)),
  `${amt(t.max_fee, t.fee_asset)}${t.payer !== t.sender ? " " + chip("sponsored", "info") : ""}`,
]);
const txCols = [{ h: "Tx id" }, { h: "Batch" }, { h: "From" }, { h: "Actions" }, { h: "Max fee", r: 1 }];

function pager(total, page, base) {
  const last = Math.max(0, Math.ceil(total / PAGE) - 1);
  return `<div class="pager"><span class="muted">${total ? page * PAGE + 1 : 0}–${Math.min(total, (page + 1) * PAGE)} of ${num(total)}</span>
    <button ${page <= 0 ? "disabled" : ""} onclick="location.hash='${base}?p=${page - 1}'">Prev</button><button ${page >= last ? "disabled" : ""} onclick="location.hash='${base}?p=${page + 1}'">Next</button></div>`;
}

const pages = {
  overview() {
    const r = camel(D.rollup), finalized = D.batches.filter((b) => b.status === "finalized").length;
    const card = (k, v, n = "") => `<div class="card"><div class="k">${k}</div><div class="v">${v}</div><div class="n">${n}</div></div>`;
    return `<h1>${esc(D.rollup_id)} <small>${esc(r.profile ?? "")} · ${esc(r.proofSystem ?? "")} · ${esc(r.privacy ?? "")}</small></h1>
      <p class="sub">State root <span class="mono">${esc(short(D.state_root, 14))}</span>${copy(D.state_root)}</p>
      <div class="cards">
        ${card("Status", esc(r.status), `layer stake ${amt(r.stakeAmount)}`)}
        ${card("Batches", num(D.batches.length), `${finalized} finalized`)}
        ${card("Frame txs", num(D.txs.length), `${D.txs.filter((t) => t.payer !== t.sender).length} sponsored`)}
        ${card("Accounts", num(D.accounts.length), "in the state tree")}
        ${card("Withdrawals", num(D.withdrawals.length), amt(D.withdrawals.reduce((s, w) => s + Number(w.amount), 0)))}
        ${card("Escrow", amt(r.escrowBalance), "L1 liquidity")}
        ${card("Members", num((r.members ?? []).length), `epoch ${esc(r.membersEpoch)}`)}
      </div>
      ${panel("Latest batches", table(batchCols, batchRows(D.batchList.slice(0, 8))), `<a href="#/batches">View all</a>`)}
      ${panel("Latest frame transactions", table(txCols, txRows(D.txs.slice(0, 10))), `<a href="#/txs">View all</a>`)}`;
  },
  batches(p) {
    const page = Math.max(0, Number(p.get("p") ?? 0));
    return `<h1>Batches</h1><p class="sub">Each batch is one Groth16 proof settled on QoreChain.</p>
      ${panel("All batches", table(batchCols, batchRows(D.batchList.slice(page * PAGE, (page + 1) * PAGE))) + pager(D.batchList.length, page, "#/batches"))}`;
  },
  batch(_p, id) {
    const b = D.batches.find((x) => x.batch_index === id);
    if (!b) return notFound(`Batch ${id}`);
    const n = Number(id), prev = n > 0, next = n < D.batches.length - 1;
    const hasW = Number(b.withdrawals_root.replace(/0/g, "").length);
    return `<div class="crumb"><a href="#/batches">Batches</a> / ${id}</div><h1>Batch ${id} ${statusChip(b.status)}</h1>
      <p class="sub">${prev ? `<a href="#/batch/${n - 1}">← ${n - 1}</a>` : ""} ${next ? `<a href="#/batch/${n + 1}">${n + 1} →</a>` : ""}</p>
      ${panel("Settlement", kv([
        ["State root", `<span class="mono">${esc(b.state_root)}</span>${copy(b.state_root)}`],
        ["Previous root", `<span class="mono">${esc(b.prev_state_root)}</span>${copy(b.prev_state_root)}`],
        ["Data hash", `<span class="mono">${esc(b.data_hash)}</span>${copy(b.data_hash)}`],
        ["Withdrawals root", hasW ? `<span class="mono">${esc(b.withdrawals_root)}</span>${copy(b.withdrawals_root)}` : chip("none")],
        ["Proof", `${chip(b.proof_type, "acc")} Groth16 · BLS12-381 · 4 public inputs`],
        ["L1 height", `submitted ${num(b.submitted_at)} · finalized ${num(b.finalized_at)}`],
        ["Transactions", num(b.tx_count)],
      ]))}
      ${panel("Watchtower checks", kv(b.findings.map((f) => [f.check, `${chip(f.ok ? "pass" : "fail", f.ok ? "ok" : "bad")} <span class="muted">${esc(f.detail)}</span>`])))}
      ${panel(`Frame transactions (${b.txs.length})`, table(txCols, txRows(b.txs.map((t, i) => ({ ...t, batch: n, pos: i })))), "")}`;
  },
  txs(p) {
    const page = Math.max(0, Number(p.get("p") ?? 0));
    return `<h1>Frame transactions</h1><p class="sub">Verify frames, optional sponsor frame, then actions.</p>
      ${panel("All transactions", table(txCols, txRows(D.txs.slice(page * PAGE, (page + 1) * PAGE))) + pager(D.txs.length, page, "#/txs"))}`;
  },
  tx(_p, id) {
    const t = D.byId.get(id) ?? D.txs.find((x) => x.id.startsWith(id));
    if (!t) return notFound(`Transaction ${id}`);
    let ai = 0;
    const frameRows = t.frames.map((f, i) => {
      let detail = "";
      if (f.mode === "VERIFY_SENDER") detail = `signed by ${t.sender === "new" ? "the key it registers" : esc(nameOf(t.sender))}`;
      else if (f.mode === "VERIFY_PAYER") detail = `fee payer ${esc(nameOf(t.payer))}`;
      else { const a = t.actions[ai++]; detail = a.kind === "transfer" ? `${amt(a.amount, a.asset)} → ${esc(nameOf(a.to))}` : a.kind === "withdraw" ? `${amt(a.amount)} → <span class="mono">${esc(a.recipient)}</span>` : `pk_commit <span class="mono">${esc(short(a.pk_commit, 12))}</span>`; }
      const atomic = f.flags & 4 ? " " + chip("atomic", "warn") : "";
      return [String(i), `<span class="frame-mode">${esc(f.mode)}</span>`, f.mode === "ACTION" ? esc(KIND[f.kind] ?? f.kind) : "—", detail + atomic];
    });
    return `<div class="crumb"><a href="#/txs">Frame transactions</a> / ${esc(short(t.id))}</div><h1>Frame transaction</h1>
      ${panel("Overview", kv([
        ["Tx id (sighash)", `<span class="mono">${esc(t.id)}</span>${copy(t.id)}`],
        ["Batch", `<a href="#/batch/${t.batch}">${t.batch}</a> · position ${t.pos}`],
        ["Sender", acct(t.sender)],
        ["Fee payer", t.payer === t.sender ? `${acct(t.payer)} ${chip("self-paid")}` : `${acct(t.payer)} ${chip("sponsored", "info")}`],
        ["Nonce", esc(t.nonce)], ["Max fee", amt(t.max_fee, t.fee_asset)], ["Expires at batch", esc(t.expiry_batch)],
        ["Signatures", `${t.signers.length} × ML-DSA-87 (${t.signers.map((s) => esc(nameOf(s))).join(", ")})`],
      ]))}
      ${panel("Frames", table([{ h: "#" }, { h: "Mode" }, { h: "Action" }, { h: "Detail" }], frameRows))}`;
  },
  accounts() {
    return `<h1>Accounts</h1><p class="sub">Leaves of the Poseidon2 state tree.</p>
      ${panel("Accounts", table([{ h: "Index" }, { h: "Name" }, { h: "Key commitment" }, { h: "QOR", r: 1 }, { h: "USD", r: 1 }, { h: "Nonce", r: 1 }],
        D.accounts.map((a) => [`<a href="#/account/${a.index}">#${a.index}</a>`, a.name ? esc(a.name) : `<span class="muted">—</span>`,
          `<span class="mono">${esc(short(a.pk_commit))}</span>`, esc((a.qor / 1e6).toLocaleString("en-US", { maximumFractionDigits: 6 })), esc((a.usd / 1e6).toLocaleString("en-US", { maximumFractionDigits: 6 })), num(a.nonce)])))}`;
  },
  account(_p, id) {
    const a = D.accounts.find((x) => String(x.index) === id || x.name === id);
    if (!a) return notFound(`Account ${id}`);
    const mine = D.txs.filter((t) => t.sender === a.index || t.payer === a.index || t.actions.some((x) => x.to === a.index));
    return `<div class="crumb"><a href="#/accounts">Accounts</a> / #${a.index}</div><h1>${esc(nameOf(a.index))}</h1>
      ${panel("Balances", kv([["Key commitment", `<span class="mono">${esc(a.pk_commit)}</span>${copy(a.pk_commit)}`], ["QOR", amt(a.qor)], ["USD", amt(a.usd, 1)], ["Nonce", num(a.nonce)]]))}
      ${panel(`Transactions (${mine.length})`, table(txCols, txRows(mine)))}`;
  },
  withdrawals() {
    return `<h1>Withdrawals</h1><p class="sub">QOR leaving the rollup. Each is committed in the batch's SHAKE-256 withdrawals tree and paid from L1 escrow.</p>
      ${panel("All withdrawals", table([{ h: "Batch" }, { h: "From" }, { h: "Recipient" }, { h: "Amount", r: 1 }, { h: "Tx" }],
        D.withdrawals.map((w) => [`<a href="#/batch/${w.batch}">${w.batch}</a>`, acct(w.sender), `<span class="mono">${esc(w.recipient)}</span>`, amt(w.amount), hashLink(w.tx, "tx")]), "No withdrawals yet."))}`;
  },
};
const notFound = (what) => `<h1>Not found</h1><p class="sub">${esc(what)} is not in this rollup's data.</p>`;

function render() {
  const [path, qs] = location.hash.slice(2).split("?");
  const [name, arg] = path.split("/");
  const p = new URLSearchParams(qs ?? "");
  const page = pages[name || "overview"];
  document.querySelectorAll("nav a").forEach((a) => a.classList.toggle("on", a.dataset.nav === (name || "")));
  $("#app").innerHTML = page ? page(p, arg) : notFound(location.hash);
  window.scrollTo(0, 0);
}

$("#search").addEventListener("submit", (e) => {
  e.preventDefault();
  const q = $("#q").value.trim(); if (!q) return;
  let to;
  if (/^\d+$/.test(q)) to = D.batches.some((b) => b.batch_index === q) ? `#/batch/${q}` : `#/account/${q}`;
  else if (/^[0-9a-f]{6,64}$/i.test(q) && D.txs.some((t) => t.id.startsWith(q.toLowerCase()))) to = `#/tx/${D.txs.find((t) => t.id.startsWith(q.toLowerCase())).id}`;
  else if (D.accounts.some((a) => a.name === q.toLowerCase())) to = `#/account/${q.toLowerCase()}`;
  else if (/^qor1/.test(q)) to = "#/withdrawals";
  else to = `#/x/${encodeURIComponent(q)}`;
  $("#q").value = ""; location.hash = to;
});
document.addEventListener("click", (e) => {
  const b = e.target.closest?.("[data-copy]"); if (!b) return;
  navigator.clipboard?.writeText(b.dataset.copy).then(() => { b.textContent = "✓"; setTimeout(() => (b.textContent = "⧉"), 900); });
});
window.addEventListener("hashchange", () => D && render());

try {
  D = await (await fetch("data.json", { cache: "no-store" })).json();
  load();
  $("#gen").textContent = `data from ${new Date(D.generated_at).toLocaleString()} · ${D.rollup_id}`;
  render();
} catch (e) {
  $("#app").innerHTML = `<h1>No data</h1><p class="sub">Generate it with <span class="mono">pnpm watchtower --id cloister-dev-2 --explorer $PWD/packages/explorer/data.json</span></p>`;
}
