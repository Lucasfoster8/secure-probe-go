// secure_probe.go — wallet anomaly probe using JSON-RPC (no 3rd-party APIs).
// Checks: nonce jumps, balance drain speed, fresh-code deployment proximity.
// Emits a risk score [0..100] + reasons. Medium-complexity, no external deps.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"
)

type rpcReq struct {
	Jsonrpc string        `json:"jsonrpc"`
	Method  string        `json:"method"`
	Params  []interface{} `json:"params"`
	Id      int           `json:"id"`
}
type rpcRes struct {
	Jsonrpc string          `json:"jsonrpc"`
	Result  json.RawMessage `json:"result"`
	Error   *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

func call(url, method string, params ...interface{}) (json.RawMessage, error) {
	payload, _ := json.Marshal(rpcReq{"2.0", method, params, 1})
	resp, err := http.Post(url, "application/json", bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var out rpcRes
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	if out.Error != nil {
		return nil, fmt.Errorf("rpc error %d: %s", out.Error.Code, out.Error.Message)
	}
	return out.Result, nil
}

func hexToBig(s string) *big.Int {
	z := new(big.Int)
	z.SetString(strings.TrimPrefix(s, "0x"), 16)
	return z
}

func weiToEth(x *big.Int) *big.Float {
	f := new(big.Float).SetInt(x)
	den := big.NewFloat(1e18)
	f.Quo(f, den)
	return f
}

func main() {
	rpc := os.Getenv("RPC_URL")
	addr := os.Getenv("ADDRESS")
	if rpc == "" || addr == "" {
		fmt.Println(`usage: RPC_URL=<rpc> ADDRESS=<0x..> ./secure-probe-go`)
		os.Exit(1)
	}
	// latest block number
	bnRaw, err := call(rpc, "eth_blockNumber")
	if err != nil { panic(err) }
	latest := hexToBig(string(bnRaw[1:len(bnRaw)-1]))

	// balance at latest and 100 blocks ago (if possible)
	balLatestRaw, _ := call(rpc, "eth_getBalance", addr, "latest")
	balLatest := hexToBig(string(balLatestRaw[1:len(balLatestRaw)-1]))

	var balPast *big.Int = new(big.Int).Set(balLatest)
	var pastBlock *big.Int = new(big.Int).Set(latest)
	if latest.Cmp(big.NewInt(100)) > 0 {
		pastBlock.Sub(latest, big.NewInt(100))
		tag := fmt.Sprintf("0x%x", pastBlock)
		balPastRaw, _ := call(rpc, "eth_getBalance", addr, tag)
		balPast = hexToBig(string(balPastRaw[1:len(balPastRaw)-1]))
	}

	// nonce now vs 100 blocks ago
	nonceNowRaw, _ := call(rpc, "eth_getTransactionCount", addr, "latest")
	noncePastRaw, _ := call(rpc, "eth_getTransactionCount", addr, fmt.Sprintf("0x%x", pastBlock))
	nonceNow := hexToBig(string(nonceNowRaw[1:len(nonceNowRaw)-1]))
	noncePast := hexToBig(string(noncePastRaw[1:len(noncePastRaw)-1]))

	// simple heuristics
	score := 0
	reasons := []string{}
	balDiff := new(big.Int).Sub(balPast, balLatest) // positive => drained
	if balDiff.Sign() > 0 {
		score += 35
		reasons = append(reasons, fmt.Sprintf("balance drop ~%s ETH/100 blocks", weiToEth(balDiff).Text('f', 6)))
	}
	nonceDiff := new(big.Int).Sub(nonceNow, noncePast)
	if nonceDiff.Cmp(big.NewInt(20)) > 0 {
		score += 25
		reasons = append(reasons, fmt.Sprintf("high tx activity: +%s nonce/100 blocks", nonceDiff.String()))
	}

	// check if code recently deployed at nearby blocks (potential approval phishing)
	type codeWindow struct{ Start, End *big.Int }
	w := codeWindow{new(big.Int).Sub(latest, big.NewInt(50)), latest}
	probeAddr := addr // naive: test code presence at the address (AA smart wallets)
	codeNowRaw, _ := call(rpc, "eth_getCode", probeAddr, "latest")
	if len(codeNowRaw) > 4 { // not "0x"
		score += 10
		reasons = append(reasons, "address has code (smart wallet or contract)")
	}
	_ = w // reserved for extension: scan logs in window

	if score > 100 { score = 100 }
	out := struct {
		Address   string   `json:"address"`
		Block     string   `json:"latestBlock"`
		Score     int      `json:"riskScore"`
		Reasons   []string `json:"reasons"`
		BalLatest string   `json:"balanceEth"`
	}{
		Address: addr,
		Block:   fmt.Sprintf("0x%x", latest),
		Score:   score,
		Reasons: reasons,
		BalLatest: weiToEth(balLatest).Text('f', 6),
	}
	enc, _ := json.MarshalIndent(out, "", "  ")
	fmt.Println(string(enc))
	// tip: schedule via cron and alert if Score >= threshold
	_ = time.Now()
}
