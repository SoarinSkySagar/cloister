/**
 * The relayer is the public door to a rollup. Users have no L1 QOR, so they hand
 * their signed frame tx to the relayer, which checks it cheaply (structure, size,
 * fee floor, rate limit) and forwards it to the sequencer. It is paid in-rollup:
 * the fee in each tx is credited to the relayer's rollup account at batch time.
 *
 * On a dedicated rollup only the sequencer may post, so the relayer forwards over
 * HTTP. On a based rollup it could post the sealed envelope itself (design.md A3).
 */
import { frameTxFromHex, structuralErrors, type FrameTx } from "@cloister/common";

export interface RelayerConfig {
  chainId: string;
  rollupId: string;
  upstream: string;          // sequencer base URL
  minFee: bigint;            // uqor-equivalent floor, same units as FrameTx.maxFee
  maxTxBytes: number;
  ratePerMinute: number;     // per client key
}

export interface Stats { accepted: number; forwarded: number; refused: number; byReason: Record<string, number> }

export class Relayer {
  readonly stats: Stats = { accepted: 0, forwarded: 0, refused: 0, byReason: {} };
  private hits = new Map<string, number[]>();

  constructor(readonly cfg: RelayerConfig, private fetcher: typeof fetch = fetch) {}

  private refuse(reason: string): never {
    this.stats.refused++;
    const k = reason.split(":")[0]!;
    this.stats.byReason[k] = (this.stats.byReason[k] ?? 0) + 1;
    throw new Error(reason);
  }

  private limited(client: string, now: number): boolean {
    const recent = (this.hits.get(client) ?? []).filter((t) => now - t < 60_000);
    recent.push(now);
    this.hits.set(client, recent);
    return recent.length > this.cfg.ratePerMinute;
  }

  /** Validate and forward one signed tx. Resolves to the sequencer's tx id. */
  async relay(hex: string, client = "anon", now = Date.now()): Promise<{ id: string }> {
    if (this.limited(client, now)) this.refuse("rate limit: too many txs this minute");
    if (typeof hex !== "string" || !/^[0-9a-f]*$/i.test(hex) || hex.length % 2) this.refuse("malformed: tx must be hex");
    if (hex.length / 2 > this.cfg.maxTxBytes) this.refuse(`too large: over ${this.cfg.maxTxBytes} bytes`);
    let tx: FrameTx;
    try { tx = frameTxFromHex(hex); } catch (e) { return this.refuse(`malformed: ${(e as Error).message}`); }
    const errs = structuralErrors(tx, { chainId: this.cfg.chainId, rollupId: this.cfg.rollupId });
    if (errs.length) this.refuse(`structure: ${errs.join("; ")}`);
    if (tx.maxFee < this.cfg.minFee) this.refuse(`fee: below the relayer minimum of ${this.cfg.minFee}`);
    this.stats.accepted++;
    const r = await this.fetcher(`${this.cfg.upstream}/tx`, {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ tx: hex }),
    });
    const body = (await r.json()) as { id?: string; error?: string };
    if (!r.ok || !body.id) this.refuse(`sequencer: ${body.error ?? r.status}`);
    this.stats.forwarded++;
    return { id: body.id! };
  }

  async status(id: string): Promise<unknown> {
    const r = await this.fetcher(`${this.cfg.upstream}/tx/${encodeURIComponent(id)}`);
    return r.json();
  }
}
