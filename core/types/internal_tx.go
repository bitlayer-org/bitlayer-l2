package types

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
)

type Data []byte

// MarshalText encodes b as a hex string with 0x prefix.
func (d Data) MarshalText() ([]byte, error) {
	return hexutil.Bytes(d[:]).MarshalText()
}

type ActionLegacy struct {
	From         common.Address `gencodec:"required" json:"from"`
	To           common.Address `gencodec:"optional" json:"to,omitempty"`
	Value        *big.Int       `gencodec:"optional" json:"value,omitempty"`
	Success      bool           `gencodec:"required" json:"success"`
	OpCode       string         `gencodec:"required" json:"opcode"`
	Depth        uint64         `gencodec:"required" json:"depth"`
	Gas          uint64         `gencodec:"required" json:"gas"`
	GasUsed      uint64         `gencodec:"required" json:"gas_used"`
	Input        Data           `gencodec:"required" json:"input"`
	Output       Data           `gencodec:"optional" json:"output,omitempty"`
	TraceAddress []uint64       `gencodec:"required" json:"trace_address"`
	Error        string         `gencodec:"optional" json:"error,omitempty"`
}

type Action struct {
	From          common.Address `gencodec:"required" json:"from"`
	To            common.Address `gencodec:"optional" json:"to,omitempty"`
	CreateAddress common.Address `gencodec:"optional" json:"create_address,omitempty"`
	Value         *big.Int       `gencodec:"optional" json:"value,omitempty"`
	Success       bool           `gencodec:"required" json:"success"`
	OpCode        string         `gencodec:"required" json:"opcode"`
	Depth         uint64         `gencodec:"required" json:"depth"`
	Gas           uint64         `gencodec:"required" json:"gas"`
	GasUsed       uint64         `gencodec:"required" json:"gas_used"`
	Input         Data           `gencodec:"required" json:"input"`
	Output        Data           `gencodec:"optional" json:"output,omitempty"`
	TraceAddress  []uint64       `gencodec:"required" json:"trace_address"`
	Error         string         `gencodec:"optional" json:"error,omitempty"`
}

type ActionConfig struct {
	From     *common.Address
	To       *common.Address
	OpCode   *string
	MinValue *big.Int
}

type ActionFrame struct {
	Action
	Calls []ActionFrame
}

type InternalTxLegacy struct {
	TxHash      common.Hash     `json:"transactionHash" gencodec:"required"`
	BlockHash   common.Hash     `json:"blockHash,omitempty"`
	BlockNumber *big.Int        `json:"blockNumber,omitempty"`
	Actions     []*ActionLegacy `json:"logs" gencodec:"required"`
}

type InternalTx struct {
	TxHash      common.Hash `json:"transactionHash" gencodec:"required"`
	BlockHash   common.Hash `json:"blockHash,omitempty"`
	BlockNumber *big.Int    `json:"blockNumber,omitempty"`
	Actions     []*Action   `json:"logs" gencodec:"required"`
}

type InternalTxForStorage InternalTx

type InternalTxsLegacy []*InternalTxLegacy
type InternalTxs []*InternalTx

func NewInternalTxsByLegacy(legacy InternalTxsLegacy) InternalTxs {
	txs := make([]*InternalTx, 0)
	for i := 0; i < len(legacy); i++ {
		actions := make([]*Action, 0)
		for j := 0; j < len(legacy[i].Actions); j++ {
			action := &Action{
				From:          legacy[i].Actions[j].From,
				To:            legacy[i].Actions[j].To,
				CreateAddress: common.Address{},
				Value:         legacy[i].Actions[j].Value,
				Success:       legacy[i].Actions[j].Success,
				OpCode:        legacy[i].Actions[j].OpCode,
				Depth:         legacy[i].Actions[j].Depth,
				Gas:           legacy[i].Actions[j].Gas,
				GasUsed:       legacy[i].Actions[j].GasUsed,
				Input:         legacy[i].Actions[j].Input,
				Output:        legacy[i].Actions[j].Output,
				TraceAddress:  legacy[i].Actions[j].TraceAddress,
				Error:         legacy[i].Actions[j].Error,
			}
			actions = append(actions, action)
		}
		tx := &InternalTx{
			TxHash:      legacy[i].TxHash,
			BlockHash:   legacy[i].BlockHash,
			BlockNumber: legacy[i].BlockNumber,
			Actions:     actions,
		}

		txs = append(txs, tx)
	}

	return txs
}
