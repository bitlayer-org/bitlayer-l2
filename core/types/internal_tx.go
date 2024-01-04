package types

import (
	"context"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/rpc"
)

type Data []byte

// MarshalText encodes b as a hex string with 0x prefix.
func (d Data) MarshalText() ([]byte, error) {
	return hexutil.Bytes(d[:]).MarshalText()
}

type Action struct {
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

type InternalTx struct {
	TxHash      common.Hash `json:"transactionHash" gencodec:"required"`
	BlockHash   common.Hash `json:"blockHash,omitempty"`
	BlockNumber *big.Int    `json:"blockNumber,omitempty"`
	Actions     []*Action   `json:"logs" gencodec:"required"`
}

type InternalTxForStorage InternalTx

type InternalTxs []*InternalTx

type ActionBackend interface {
	HeaderByHash(ctx context.Context, hash common.Hash) (*Header, error)
	HeaderByNumber(ctx context.Context, number rpc.BlockNumber) (*Header, error)
	BlockByHash(ctx context.Context, hash common.Hash) (*Block, error)
	BlockByNumber(ctx context.Context, number rpc.BlockNumber) (*Block, error)
	GetTransaction(ctx context.Context, txHash common.Hash) (*Transaction, common.Hash, uint64, uint64, error)
	ChainDb() ethdb.Database
}

type ReadInternalTxBackend interface {
	ReadInternalTxs(db ethdb.Reader, hash common.Hash, number uint64) []*InternalTx
}

// blockByNumber is the wrapper of the chain access function offered by the backend.
// It will return an error if the block is not found.
func BlockByNumber(b ActionBackend, ctx context.Context, number rpc.BlockNumber) (*Block, error) {
	block, err := b.BlockByNumber(ctx, number)
	if err != nil {
		return nil, err
	}
	if block == nil {
		return nil, fmt.Errorf("block #%d not found", number)
	}
	return block, nil
}

// getInnerTx returns internal txs
func GetInnerTx(b ActionBackend, txb ReadInternalTxBackend, block *Block) (InternalTxs, error) {
	txs := txb.ReadInternalTxs(b.ChainDb(), block.Hash(), block.NumberU64())

	for _, tx := range txs {
		tx.BlockHash = block.Hash()
		tx.BlockNumber = block.Number()
	}

	return txs, nil
}

func FilterAction(b ActionBackend, actions []*Action, filter *ActionConfig) []*Action {
	if filter == nil {
		return actions
	}

	res := make([]*Action, 0, len(actions))

	for _, act := range actions {
		if filter.OpCode != nil && *filter.OpCode != act.OpCode {
			continue
		}

		if filter.MinValue != nil && filter.MinValue.Cmp(act.Value) > 0 {
			continue
		}

		if filter.From != nil && *filter.From != act.From {
			continue
		}

		if filter.To != nil && *filter.To != act.To {
			continue
		}

		res = append(res, act)
	}

	return res
}

// TraceActionByBlockHash return actions of internal txs by block hash
func TraceActionByBlockHash(b ActionBackend, txb ReadInternalTxBackend, ctx context.Context, hash common.Hash) (InternalTxs, error) {
	block, err := b.BlockByHash(ctx, hash)
	if err != nil {
		return nil, err
	}

	if block == nil {
		return nil, fmt.Errorf("block %#x not found", hash)
	}
	return GetInnerTx(b, txb, block)
}

// TraceActionByBlockNumber return actions of internal txs by block number
func TraceActionByBlockNumber(b ActionBackend, txb ReadInternalTxBackend, ctx context.Context, number rpc.BlockNumber, filter *ActionConfig) (InternalTxs, error) {
	block, err := BlockByNumber(b, ctx, number)
	if err != nil {
		return nil, err
	}

	// Trace the block if it was found
	if block == nil {
		return nil, fmt.Errorf("block #%d not found", number)
	}

	iTx, err := GetInnerTx(b, txb, block)
	if err != nil {
		return nil, err
	}

	res := make([]*InternalTx, 0)
	for _, tx := range iTx {
		tx.Actions = FilterAction(b, tx.Actions, filter)
		if len(tx.Actions) > 0 {
			res = append(res, tx)
		}
	}

	return res, nil
}

// TraceActionByBlockNumber return actions of internal txs by tx hash
func TraceActionByTxHash(b ActionBackend, txb ReadInternalTxBackend, ctx context.Context, hash common.Hash, filter *ActionConfig) (*InternalTx, error) {
	tx, blkHash, _, _, err := b.GetTransaction(ctx, hash)
	if err != nil {
		return nil, err
	}

	if tx == nil {
		return nil, fmt.Errorf("tx #%s not found", hash)
	}

	block, err := b.BlockByHash(ctx, blkHash)
	if err != nil {
		return nil, err
	}

	// Trace the block if it was found
	if block == nil {
		return nil, fmt.Errorf("block #%s not found", hash)
	}

	txs, err := GetInnerTx(b, txb, block)
	if err != nil {
		return nil, err
	}

	for _, t := range txs {
		if t.TxHash == hash {
			t.Actions = FilterAction(b, t.Actions, filter)
			return t, nil
		}
	}

	return nil, nil
}
