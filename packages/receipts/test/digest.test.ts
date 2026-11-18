import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { digestOfTerms, domainConst, txDigest, NEW_ACCOUNT_SENDER, type DigestTx } from "../src/digest.ts";
import { toHex } from "../src/inclusion.ts";

const cases = JSON.parse(readFileSync(join(import.meta.dirname, "..", "..", "..", "spec", "vectors", "digest.json"), "utf8")) as any[];

test("the digest reproduces the Go reference for every golden case", () => {
  assert.ok(cases.length >= 4);
  for (const c of cases) {
    assert.equal(toHex(domainConst(c.chain_id, c.rollup_id)), c.domain, `${c.name}: domain`);
    const d = digestOfTerms({
      chainId: c.chain_id, rollupId: c.rollup_id, signedSender: c.signed_sender, nonce: BigInt(c.nonce), expiry: BigInt(c.expiry), notBefore: BigInt(c.not_before),
      payer: c.payer, feeAsset: c.fee_asset, maxFee: BigInt(c.max_fee), parties: c.parties,
      actions: c.actions.map((a: any) => ({ code: a.code, asset: a.asset, amount: BigInt(a.amount), from: a.from, to: a.to, aux: BigInt("0x" + a.aux), atomic: a.atomic })),
    });
    assert.equal(toHex(d), c.digest, c.name);
  }
});

test("the digest of a transaction as the prover received it is the golden digest", () => {
  const swap: DigestTx = { sender: 2, payer: 2, fee_asset: 0, fee: 10_000, parties: [3], expiry: 99, not_before: 7, actions: [
    { kind: "transfer", from: 2, to: 3, asset: 1, amount: 5, atomic: true },
    { kind: "withdraw", from: 3, recipient: "qor1plfn9jpxnavtxsrwe0sg6cls5z9amy8p3tg9nu", amount: 500_000, atomic: true }] };
  assert.equal(toHex(txDigest("qorechain-diana", "cloister-dev-3", 4n, swap)), cases[1].digest);

  const sponsored: DigestTx = { sender: 3, payer: 0, fee_asset: 0, fee: 10_000, expiry: 53, actions: [{ kind: "transfer", to: 2, asset: 0, amount: 1_000_000 }] };
  assert.equal(toHex(txDigest("qorechain-diana", "cloister-dev-3", 1n, sponsored)), cases[0].digest);

  // a new account: the digest carries the sentinel while the executing tx carries the assigned index 7
  const reg: DigestTx = { sender: 7, payer: 0, fee_asset: 0, fee: 10_000, new_account: true, actions: [{ kind: "register_key", pk_commit: "3039" }] };
  assert.equal(toHex(txDigest("qorechain-diana", "cloister-dev-3", 0n, reg)), cases[2].digest);
  assert.equal(NEW_ACCOUNT_SENDER, cases[2].signed_sender);

  const none: DigestTx = { sender: 5, payer: 5, fee_asset: 1, fee: 0, actions: [] }; // no fee: the fee asset is not committed
  assert.equal(toHex(txDigest("qorechain-diana", "cloister-dev-3", 0n, none)), cases[3].digest);
});

test("changing any term of a transaction changes its digest", () => {
  const base: DigestTx = { sender: 2, payer: 2, fee_asset: 0, fee: 10_000, parties: [3], expiry: 99, not_before: 7, actions: [
    { kind: "transfer", from: 2, to: 3, asset: 1, amount: 5, atomic: true },
    { kind: "withdraw", from: 3, recipient: "qor1plfn9jpxnavtxsrwe0sg6cls5z9amy8p3tg9nu", amount: 500_000, atomic: true }] };
  const d0 = txDigest("qorechain-diana", "cloister-dev-3", 4n, base);
  const v: Record<string, bigint> = {
    nonce: txDigest("qorechain-diana", "cloister-dev-3", 5n, base),
    chain: txDigest("other", "cloister-dev-3", 4n, base),
    rollup: txDigest("qorechain-diana", "other", 4n, base),
    sender: txDigest("qorechain-diana", "cloister-dev-3", 4n, { ...base, sender: 9 }),
    payer: txDigest("qorechain-diana", "cloister-dev-3", 4n, { ...base, payer: 9 }),
    fee: txDigest("qorechain-diana", "cloister-dev-3", 4n, { ...base, fee: 10_001 }),
    expiry: txDigest("qorechain-diana", "cloister-dev-3", 4n, { ...base, expiry: 100 }),
    notBefore: txDigest("qorechain-diana", "cloister-dev-3", 4n, { ...base, not_before: 8 }),
    party: txDigest("qorechain-diana", "cloister-dev-3", 4n, { ...base, parties: [4] }),
    amount: txDigest("qorechain-diana", "cloister-dev-3", 4n, { ...base, actions: [{ ...base.actions[0]!, amount: 6 }, base.actions[1]!] }),
    atomic: txDigest("qorechain-diana", "cloister-dev-3", 4n, { ...base, actions: [{ ...base.actions[0]!, atomic: false }, base.actions[1]!] }),
    recipient: txDigest("qorechain-diana", "cloister-dev-3", 4n, { ...base, actions: [base.actions[0]!, { ...base.actions[1]!, recipient: "qor12jmzemjntpkfr4ler3rdwpemrv3qg7pzxkpxkm" }] }),
    drop: txDigest("qorechain-diana", "cloister-dev-3", 4n, { ...base, actions: [base.actions[0]!] }),
  };
  for (const [k, d] of Object.entries(v)) assert.notEqual(d, d0, `changing the ${k} must change the digest`);
});
