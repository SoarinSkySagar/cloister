package ledger

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"testing"
)

type withdrawalVector struct {
	Name  string `json:"name"`
	Input struct {
		ChainID     string `json:"chain_id"`
		RollupID    string `json:"rollup_id"`
		Withdrawals []struct {
			Recipient string `json:"recipient"`
			Amount    string `json:"amount"`
		} `json:"withdrawals"`
	} `json:"input"`
	Expected struct {
		Root     string `json:"root"`
		RootModR string `json:"root_mod_r"`
	} `json:"expected"`
}

// The same file is generated from @qorechain/rdk withdrawalsTree
// (scripts/spike gen-vectors). Native Go and the circuit must both match it.
func TestWithdrawalVectorsMatchRDK(t *testing.T) {
	raw, err := os.ReadFile("../../spec/vectors/withdrawals.json")
	if err != nil {
		t.Fatal(err)
	}
	var vs []withdrawalVector
	if err := json.Unmarshal(raw, &vs); err != nil {
		t.Fatal(err)
	}
	for _, v := range vs {
		t.Run(v.Name, func(t *testing.T) {
			cfg := testConfig()
			cfg.ChainID, cfg.RollupID = v.Input.ChainID, v.Input.RollupID
			var ws []Withdrawal
			var b Batch
			for _, w := range v.Input.Withdrawals {
				amt, _ := strconv.ParseUint(w.Amount, 10, 64)
				ws = append(ws, Withdrawal{w.Recipient, amt})
				b.Txs = append(b.Txs, TxIn{Sender: treas, Payer: treas, Relayer: relay, Actions: []ActionIn{
					{Kind: "withdraw", Recipient: w.Recipient, Amount: amt},
				}})
			}
			root := WithdrawalsRoot(cfg.ChainID, cfg.RollupID, ws)
			if hex.EncodeToString(root[:]) != v.Expected.Root {
				t.Fatalf("native root %x, rdk %s", root, v.Expected.Root)
			}
			w, _, _ := build(t, cfg, b, Options{})
			if got := fmt.Sprintf("%064x", w.WithdrawalsRoot); got != v.Expected.RootModR {
				t.Fatalf("public input %s, rdk %s", got, v.Expected.RootModR)
			}
			if err := solves(t, cfg, w); err != nil {
				t.Fatalf("circuit rejects the RDK root: %v", err)
			}
		})
	}
}
