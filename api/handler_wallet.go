package api

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/gin-gonic/gin"
)

type walletValidateRequest struct {
	PrivateKey string `json:"private_key"`
}

type walletValidateResponse struct {
	Valid        bool   `json:"valid"`
	Address      string `json:"address,omitempty"`
	BalanceUSDC  string `json:"balance_usdc,omitempty"`
	Claw402Status string `json:"claw402_status"` // "ok", "unreachable", "error"
	Error        string `json:"error,omitempty"`
}

const (
	baseRPCURL      = "https://mainnet.base.org"
	usdcContractBase = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
	usdcDecimals     = 6
)

func (s *Server) handleWalletValidate(c *gin.Context) {
	var req walletValidateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, walletValidateResponse{
			Valid: false,
			Error: "invalid request body",
		})
		return
	}

	pk := req.PrivateKey

	// Validate format
	if !strings.HasPrefix(pk, "0x") {
		c.JSON(http.StatusOK, walletValidateResponse{
			Valid: false,
			Error: "missing 0x prefix",
		})
		return
	}

	if len(pk) != 66 {
		c.JSON(http.StatusOK, walletValidateResponse{
			Valid: false,
			Error: fmt.Sprintf("should be 66 characters, got %d", len(pk)),
		})
		return
	}

	hexPart := pk[2:]
	if _, err := hex.DecodeString(hexPart); err != nil {
		c.JSON(http.StatusOK, walletValidateResponse{
			Valid: false,
			Error: "contains invalid hex characters",
		})
		return
	}

	// Derive address
	privateKey, err := crypto.HexToECDSA(hexPart)
	if err != nil {
		c.JSON(http.StatusOK, walletValidateResponse{
			Valid: false,
			Error: "invalid private key",
		})
		return
	}

	address := crypto.PubkeyToAddress(privateKey.PublicKey)
	addrHex := address.Hex()

	// Query USDC balance (async-ish, but sequential for simplicity)
	balanceStr := queryUSDCBalance(addrHex)

	// Check claw402 health
	claw402Status := checkClaw402Health()

	c.JSON(http.StatusOK, walletValidateResponse{
		Valid:        true,
		Address:      addrHex,
		BalanceUSDC:  balanceStr,
		Claw402Status: claw402Status,
	})
}

func queryUSDCBalance(address string) string {
	// Build balanceOf(address) call data
	// Function selector: 0x70a08231
	// Pad address to 32 bytes
	addrNoPre := strings.TrimPrefix(strings.ToLower(address), "0x")
	data := "0x70a08231" + fmt.Sprintf("%064s", addrNoPre)

	payload := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "eth_call",
		"params": []interface{}{
			map[string]string{
				"to":   usdcContractBase,
				"data": data,
			},
			"latest",
		},
		"id": 1,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return "0.00"
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(baseRPCURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return "0.00"
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "0.00"
	}

	var rpcResp struct {
		Result string `json:"result"`
	}
	if err := json.Unmarshal(respBody, &rpcResp); err != nil {
		return "0.00"
	}

	// Parse hex result
	hexStr := strings.TrimPrefix(rpcResp.Result, "0x")
	if hexStr == "" || hexStr == "0" {
		return "0.00"
	}

	balance := new(big.Int)
	balance.SetString(hexStr, 16)

	// Convert to float with 6 decimals
	divisor := new(big.Int).Exp(big.NewInt(10), big.NewInt(usdcDecimals), nil)
	whole := new(big.Int).Div(balance, divisor)
	remainder := new(big.Int).Mod(balance, divisor)

	return fmt.Sprintf("%d.%06d", whole, remainder)
}

func checkClaw402Health() string {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("https://claw402.ai/health")
	if err != nil {
		return "unreachable"
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return "ok"
	}
	return "error"
}
