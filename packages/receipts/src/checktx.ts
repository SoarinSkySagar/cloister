/**
 * Is this inclusion proof for THIS signed transaction? (spec/inclusion.md, "Verifying", step 5.) Pure: it compares the
 * proof's record with the transaction and says nothing about the chain (verifyInclusion does that).
 */
import { NEW_ACCOUNT, toLedgerTx, type FrameTx } from "@cloister/common";
import { txDigest } from "./digest.ts";
import { toHex, type InclusionProof } from "./inclusion.ts";

export interface TxCheck {
  /** Problems found: empty means the record is the transaction's. */
  problems: string[];
  /** Per action (in the transaction's order): did it apply, according to the record? */
  applied: boolean[];
}

export function checkTxAgainstProof(proof: InclusionProof, tx: FrameTx): TxCheck {
  const rec = proof.record;
  const problems: string[] = [];
  if (proof.version !== 2 || rec.digest === undefined) {
    return { problems: ["a version 1 proof carries no digest, so it cannot be tied to a signed transaction"], applied: [] };
  }
  if (tx.chainId !== proof.chainId || tx.rollupId !== proof.rollupId) problems.push("the transaction is for another chain or rollup");
  const ledger = toLedgerTx(tx, { relayer: 0, senderIndex: tx.sender === NEW_ACCOUNT ? rec.sender : undefined });
  if (rec.sender !== ledger.sender) problems.push(`the record's sender is #${rec.sender}, the transaction's is #${ledger.sender}`);
  if (BigInt(rec.nonceBefore) !== tx.nonce) problems.push(`the record's nonce is ${rec.nonceBefore}, the transaction's is ${tx.nonce}`);
  if (toHex(txDigest(proof.chainId, proof.rollupId, tx.nonce, ledger)) !== rec.digest) {
    problems.push("the digest of this transaction is not the record's digest: what was executed is not what was signed");
  }
  const applied = ledger.actions.map((_, k) => (rec.moves[1 + k]?.code ?? 0) !== 0);
  return { problems, applied };
}
