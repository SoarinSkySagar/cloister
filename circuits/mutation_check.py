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
    "tx root commits the parties": ("recFields = append(recFields, api.Mul(tx.PartyActive[i], api.Add(tx.Party[i], 1)))", "_ = i"),
    "record binds the withdrawal recipient": ("api.Mul(rcSel, mv.IsWithdraw)", "api.Mul(0, mv.IsWithdraw)"),
    "inactive slot's record is zero": ("recLeaves = append(recLeaves, api.Mul(tx.Active, x.md(recFields)))", "recLeaves = append(recLeaves, x.md(recFields))"),
    "batch counter increments": ("Nonce: api.Add(n, 1), Orders: 0}", "Nonce: n, Orders: 0}"),
    "withdraw cannot be QOR-excluded (only QOR leaves)": ("api.AssertIsEqual(api.Mul(mv.IsWithdraw, mv.Asset), 0)", "_ = mv"),
    "key can never overwrite a key": ("api.AssertIsEqual(api.Mul(mv.IsRegister, f.Pk), 0)", "_ = f"),
    "key can never be empty": ("api.AssertIsEqual(api.Mul(mv.IsRegister, api.IsZero(mv.PkCommit)), 0)", "_ = mv"),
    "inactive tx has only no-ops": ("api.AssertIsEqual(api.Mul(any, api.Sub(1, tx.Active)), 0)", "_ = any"),
    # ---- ledger rules from circuit v1 ----
    "tx Active flag is boolean": ("api.AssertIsBoolean(tx.Active)", "_ = tx"),
    "move kind flags are boolean": ("\t\t\t\tapi.AssertIsBoolean(b)\n", "\t\t\t\t_ = b\n"),
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
