# Watchtower verdict (v1)

A **verdict** is a member watchtower's signed statement about one batch: what it decrypted and checked, and whether everything passed. It lets the public see that someone with access to the sealed data looked at it, without revealing the data. Design: [design.md §A6b](../design.md).

## Fields

| Field | Type | Meaning |
|---|---|---|
| `version` | 1 | |
| `chainId` | string | e.g. `qorechain-diana` |
| `rollupId` | string | `^[a-z0-9][a-z0-9._-]{2,63}$` |
| `batchIndex` | integer ≥ 0 | |
| `stateRoot` | 64 hex, lower case | the batch's state root as the chain holds it, left-padded to 64 |
| `dataHash` | 64 hex, lower case | the batch's `data_hash` as the chain holds it |
| `watchtower` | string | the member's L1 address (`qor1…`) |
| `result` | `pass` \| `fail` | `pass` only if every listed check passed |
| `scope` | `bundle` \| `link-only` | `link-only` for batches posted before the bundle format: only the hash link was checked |
| `checks` | list of `{name, ok}` | names `[a-z]+`, unique, sorted by name |
| `signedAt` | integer | unix seconds, informational |
| `signature` | hex | ML-DSA-87 signature over the message below |

Checks used by the Cloister watchtower: `link`, `decrypt`, `index`, `count`, `structure`, `signature` (every party's too), `window` (every tx inside the time window it signed), and `legacy` for `link-only` batches.

## Signed message

```
msg = SHAKE-256/32( "cloister/verdict/v1\n"
                  + chainId + "\n" + rollupId + "\n" + batchIndex + "\n"
                  + stateRoot + "\n" + dataHash + "\n" + watchtower + "\n"
                  + result + "\n" + scope + "\n"
                  + checks.map(c => c.name + "=" + (c.ok ? "1" : "0")).join(",") + "\n"
                  + signedAt )
signature = ML-DSA-87.sign(secretKey, msg)
```

All strings are UTF-8. A verifier first rejects any field containing `\n`, any check name outside `[a-z]+`, unsorted or duplicate checks, and `result: pass` with a failing check.

## Accepting a verdict

A verdict counts only if all of these hold:

1. The structure above is valid, and `signature` verifies over `msg`.
2. The ML-DSA-87 public key is **read from the chain** for `watchtower` (never taken from the verdict).
3. `watchtower` is currently a member of the rollup.
4. `chainId`, `rollupId`, `batchIndex`, `stateRoot` and `dataHash` equal what the chain holds for that batch.

A `result: fail` verdict that passes 1–4 is a valid *warning*: it is shown, never hidden.

## What it does not prove

It is an off-chain signature. It proves that a key registered on chain, belonging to a current member, signed this statement. It does not prove the statement is true: members who collude can sign a false `pass`. It shortens the trust assumption to "at least one member watchtower is honest and verifiable by the public over time", and gives that member something to be held accountable for.

Golden vector: [vectors/verdict.json](vectors/verdict.json).
