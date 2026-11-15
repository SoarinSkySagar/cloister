#!/usr/bin/env python3
"""
Mutation check for circuits/ledger: remove one constraint at a time and confirm that a test fails.
A negative test that still passes without its constraint is rejecting for the wrong reason.

    python3 circuits/mutation_check.py          # all mutations, about 15 s each
    python3 circuits/mutation_check.py window   # only mutations whose name contains "window"

circuit.go is restored afterwards (and on Ctrl-C). Exit code 1 if any mutation is NOT caught.
"""
import os, subprocess, sys, shutil

os.chdir(os.path.dirname(os.path.abspath(__file__)))   # runs from anywhere

SRC = "ledger/circuit.go"
MUTATIONS = {
    "party auth rule": ("api.AssertIsEqual(api.Mul(any, notAuth), 0)", "_ = notAuth"),
    "register_key is sender-only": ("api.AssertIsEqual(api.Mul(mv.IsRegister, api.Sub(mv.From.Index, tx.Sender.Index)), 0)", "_ = tx"),
    "window: not_before bound": ("x.u64(api.Mul(tx.Active, api.Sub(n, tx.NotBefore)))", "_ = n"),
    "window: expiry bound": ("x.u64(api.Mul(tx.Active, api.Sub(tx.Expiry, n)))", "_ = n"),
    "window: expiry 64-bit range": ("x.u64(tx.Expiry)\n", "_ = tx.Expiry\n"),
    "window: not_before 64-bit range": ("x.u64(tx.NotBefore)\n", "_ = tx.NotBefore\n"),
    "no account update may touch the log leaf": ("x.api.AssertIsDifferent(u.Index, x.logIndex)", "_ = u"),
    "log update is at LOG_INDEX": ("api.AssertIsEqual(c.Log.Index, x.logIndex)", "_ = c"),
    "old log leaf: qor is zero": ("api.AssertIsEqual(c.Log.Old.Qor, 0)", "_ = c"),
    "old log leaf: usd is zero": ("api.AssertIsEqual(c.Log.Old.Usd, 0)", "_ = c"),
    "old log leaf: orders is zero": ("api.AssertIsEqual(c.Log.Old.Orders, 0)", "_ = c"),
    "party flags are boolean": ("api.AssertIsBoolean(tx.PartyActive[i])", "_ = i"),
    "tx root commits the parties": ("partyFields[i] = api.Mul(tx.PartyActive[i], api.Add(tx.Party[i], 1))", "partyFields[i] = 0"),
    "withdraw: planned recipient commitment is the slot's": ("api.AssertIsEqual(api.Mul(eW, api.Sub(mv.PkCommit, rcSel)), 0)", "_ = rcSel"),
    "aux belongs to register and withdraw only": ("api.AssertIsEqual(api.Mul(mv.PkCommit, api.Sub(1, api.Add(mv.IsRegister, mv.IsWithdraw))), 0)", "_ = mv"),
    "inactive slot's record is zero": ("recLeaves = append(recLeaves, api.Mul(tx.Active, x.md(recFields)))", "recLeaves = append(recLeaves, x.md(recFields))"),
    "batch counter increments": ("Nonce: api.Add(n, 1), Orders: 0}", "Nonce: n, Orders: 0}"),
    "withdraw cannot be QOR-excluded (only QOR leaves)": ("api.AssertIsEqual(api.Mul(mv.IsWithdraw, mv.Asset), 0)", "_ = mv"),
    "key can never overwrite a key": ("api.AssertIsEqual(api.Mul(eR, f.Pk), 0)", "_ = f"),
    "key can never be empty": ("api.AssertIsEqual(api.Mul(mv.IsRegister, api.IsZero(mv.PkCommit)), 0)", "_ = mv"),
    "every fee is paid to the configured relayer": ("api.AssertIsEqual(api.Mul(mv.IsTransfer, api.Sub(mv.To.Index, relayer)), 0)", "_ = relayer"),
    "inactive tx has only no-ops": ("api.AssertIsEqual(api.Mul(any, api.Sub(1, tx.Active)), 0)", "_ = any"),
    # ---- ledger rules from circuit v1 ----
    "tx Active flag is boolean": ("api.AssertIsBoolean(tx.Active)", "_ = tx"),
    "move kind flags are boolean": ("\t\t\t\tapi.AssertIsBoolean(b)\n", "\t\t\t\t_ = b\n"),
    # ---- circuit v3: skips must be justified; the record binds what was signed (findings F2, F3, F6) ----
    "skip flag is boolean": ("api.AssertIsBoolean(mv.Skip)", "_ = mv"),
    "atomic flag is boolean": ("api.AssertIsBoolean(mv.Atomic)", "_ = mv"),
    "an empty slot carries no atomic flag": ("api.AssertIsEqual(api.Mul(mv.Atomic, api.Sub(1, any)), 0)", "_ = any"),
    "the fee always applies": ("api.AssertIsEqual(mv.Skip, 0)", "_ = mv"),
    "the fee move has no atomic flag": ("api.AssertIsEqual(mv.Atomic, 0)", "_ = mv"),
    "atomic groups are skipped as a whole": ("api.AssertIsEqual(api.Mul(link[a], api.Sub(skips[a], skips[a+1])), 0)", "_ = link"),
    "a skip must be justified": ("api.AssertIsEqual(api.Mul(skips[a], none), 0)", "_ = none"),
    "tentative: unlinked moves are not part of the group": ("conn = api.Mul(conn, api.Mul(p.atomic, acts[i+1].atomic))", "_ = conn"),
    "justification: insufficient balance": ("nf(api.Mul(pVal, insufficient))", "api.Add(1, api.Mul(0, insufficient))"),
    "justification: credit overflow": ("nf(api.Mul(mv.IsTransfer, overflow))", "api.Add(1, api.Mul(0, overflow))"),
    "justification: withdrawal slots full": ("nf(api.Mul(mv.IsWithdraw, full))", "api.Add(1, 0)"),
    "justification: key already set": ("nf(api.Mul(mv.IsRegister, keyExists))", "api.Add(1, api.Mul(0, keyExists))"),
    "tentative: earlier debits of the payer": ("balFrom = api.Sub(balFrom, api.Mul(debit, api.IsZero(api.Sub(p.from, mv.From.Index))))", "_ = debit"),
    "tentative: earlier credits of the payer": ("balFrom = api.Add(balFrom, api.Mul(credit, api.IsZero(api.Sub(p.to, mv.From.Index))))", "_ = credit"),
    "tentative: earlier debits of the receiver": ("balTo = api.Sub(balTo, api.Mul(debit, api.IsZero(api.Sub(p.from, mv.To.Index))))", "_ = debit"),
    "tentative: earlier credits of the receiver": ("balTo = api.Add(balTo, api.Mul(credit, api.IsZero(api.Sub(p.to, mv.To.Index))))", "_ = credit"),
    "tentative: the move's own debit of the receiver": ("balTo = api.Sub(balTo, api.Mul(mv.IsTransfer, mv.Amount, api.IsZero(api.Sub(mv.From.Index, mv.To.Index))))", "_ = balTo"),
    "tentative: earlier withdrawals": ("wTent = api.Add(wTent, api.Mul(conn, p.isW))", "_ = wTent"),
    "tentative: earlier key registrations": ("keyHit = api.Add(keyHit, api.Mul(conn, p.isR, api.IsZero(api.Sub(p.from, mv.From.Index))))", "_ = keyHit"),
    "tentative: only the same asset": ("same := api.IsZero(api.Sub(p.asset, mv.Asset))", "same := api.Add(1, 0)"),
    "signed sender is the sender or the new-account sentinel": ("api.AssertIsEqual(api.Mul(api.Sub(tx.SignedSender, tx.Sender.Index), api.Sub(tx.SignedSender, newAccount)), 0)", "_ = newAccount"),
    "a new account is an empty leaf": ("api.AssertIsEqual(api.Mul(isNew, f), 0)", "_, _ = isNew, f"),
    "a new account's tx registers a key": ("api.AssertIsEqual(api.Mul(isNew, api.IsZero(regCount)), 0)", "_ = regCount"),
    "fee is at most the signed max fee": ("x.u64(api.Mul(tx.Active, api.Sub(tx.MaxFee, feeAmt)))", "_ = feeAmt"),
    "digest binds the chain and rollup": ("tx.Expiry, tx.NotBefore, tx.Moves[0].From.Index, feeAsset, tx.MaxFee}", "tx.Expiry, tx.NotBefore, tx.Moves[0].From.Index, feeAsset, tx.MaxFee}\n\t\tdfields[1] = 0"),
    "digest binds the actions": ("dfields = append(dfields, digestActs...)", "_ = digestActs"),
    "digest binds the parties": ("dfields = append(dfields, partyFields...)", "_ = partyFields"),
    "digest binds the payer": ("tx.Expiry, tx.NotBefore, tx.Moves[0].From.Index, feeAsset, tx.MaxFee}", "tx.Expiry, tx.NotBefore, 0, feeAsset, tx.MaxFee}"),
    "digest binds the fee asset": ("tx.Expiry, tx.NotBefore, tx.Moves[0].From.Index, feeAsset, tx.MaxFee}", "tx.Expiry, tx.NotBefore, tx.Moves[0].From.Index, api.Mul(0, feeAsset), tx.MaxFee}"),
    "digest binds the max fee": ("tx.Expiry, tx.NotBefore, tx.Moves[0].From.Index, feeAsset, tx.MaxFee}", "tx.Expiry, tx.NotBefore, tx.Moves[0].From.Index, feeAsset, 0}"),
    "digest binds the signed sender": ("[]frontend.Variable{DigestTag, c.domain, tx.SignedSender,", "[]frontend.Variable{DigestTag, c.domain, 0,"),
    "record carries the digest": ("recFields := []frontend.Variable{TxRecordTag, digest,", "recFields := []frontend.Variable{TxRecordTag, api.Mul(0, digest),"),
    "a move has at most one kind": ("api.AssertIsBoolean(any)", "_ = any"),
    "fee move cannot withdraw": ("api.AssertIsEqual(mv.IsWithdraw, 0)", "_ = mv"),
    "fee move cannot register a key": ("api.AssertIsEqual(mv.IsRegister, 0)", "_ = mv"),
    "amount is below 2^64": ("x.u64(mv.Amount)", "_ = mv"),
    "debited balance stays non-negative (qor)": ("x.u64(nf.Qor)", "_ = nf"),
    "debited balance stays non-negative (usd)": ("x.u64(nf.Usd)", "_ = nf"),
    "credited balance cannot overflow (qor)": ("x.u64(nt.Qor)", "_ = nt"),
    "credited balance cannot overflow (usd)": ("x.u64(nt.Usd)", "_ = nt"),
    "sender nonce increments with the tx": ("api.Add(s.Nonce, tx.Active)", "s.Nonce"),
    "at most W withdrawals": ("api.AssertIsEqual(prod, 0)", "_ = prod"),
    "final root equals the public state_root": ("api.AssertIsEqual(root, c.StateRoot)", "_ = root"),
    "withdrawals_root equals the public input": ("api.AssertIsEqual(wroot, c.WithdrawalsRoot)", "_ = wroot"),
    "data_hash squared is bound": ("api.AssertIsEqual(api.Mul(c.DataHash, c.DataHash), c.DataHashSq)", "_ = c"),
    "batch 0 starts from the genesis root": ("api.Select(api.IsZero(c.PrevStateRoot), c.genesis, c.PrevStateRoot)", "api.Add(c.PrevStateRoot, 0)"),
}


def main():
    want = sys.argv[1] if len(sys.argv) > 1 else ""
    good = open(SRC).read()
    shutil.copy(SRC, "/tmp/circuit.go.orig")
    missed, ran = [], 0
    try:
        for name, (old, new) in MUTATIONS.items():
            if want and want not in name:
                continue
            if old not in good:
                print(f"{name:52s} PATTERN NOT FOUND (the circuit changed; update this table)")
                missed.append(name)
                continue
            open(SRC, "w").write(good.replace(old, new, 1))
            r = subprocess.run(["go", "test", "./ledger", "-count=1"], capture_output=True, text=True)
            failed = [l.split()[2] for l in r.stdout.splitlines() if l.startswith("--- FAIL")]
            ran += 1
            if failed:
                print(f"{name:52s} caught by {', '.join(failed[:2])}{' ...' if len(failed) > 2 else ''}")
            elif "build failed" in r.stdout or "FAIL" in r.stdout:
                print(f"{name:52s} build failure: {r.stdout[:100]!r}")
                missed.append(name)
            else:
                print(f"{name:52s} NOT CAUGHT")
                missed.append(name)
    finally:
        open(SRC, "w").write(good)
    print(f"\n{ran} mutations run, {len(missed)} not caught" + (": " + ", ".join(missed) if missed else ""))
    sys.exit(1 if missed else 0)

main()
