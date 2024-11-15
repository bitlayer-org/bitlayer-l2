package types

import (
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
)

// TraceFilterRequest represents the arguments for trace_filter
type TraceFilterRequest struct {
	FromBlock   *hexutil.Uint64  `json:"fromBlock"`
	ToBlock     *hexutil.Uint64  `json:"toBlock"`
	FromAddress []common.Address `json:"fromAddress"`
	ToAddress   []common.Address `json:"toAddress"`
	Mode        TraceFilterMode  `json:"mode"`
	After       *uint64          `json:"after"`
	Count       *uint64          `json:"count"`
}

type TraceFilterMode string

const (
	// TraceFilterModeUnion is default mode for TraceFilter.
	// Unions results referred to addresses from FromAddress or ToAddress
	TraceFilterModeUnion = "union"
	// TraceFilterModeIntersection retrieves results referred to addresses provided both in FromAddress and ToAddress
	TraceFilterModeIntersection = "intersection"
)

// ParityTrace A trace in the desired format (Parity/OpenEthereum) See: https://openethereum.github.io/wiki/JSONRPC-trace-module
type ParityTrace struct {
	// Do not change the ordering of these fields -- allows for easier comparison with other clients
	Action              interface{}  `json:"action"` // Can be either CallTraceAction or CreateTraceAction
	BlockHash           *common.Hash `json:"blockHash,omitempty"`
	BlockNumber         *uint64      `json:"blockNumber,omitempty"`
	Error               string       `json:"error,omitempty"`
	Result              interface{}  `json:"result"`
	Subtraces           int          `json:"subtraces"`
	TraceAddress        []uint64     `json:"traceAddress"`
	TransactionHash     *common.Hash `json:"transactionHash,omitempty"`
	TransactionPosition *uint64      `json:"transactionPosition,omitempty"`
	Type                string       `json:"type"`
}

// ParityTraces An array of parity traces
type ParityTraces []ParityTrace

type CallTraceAction struct {
	From     common.Address `json:"from"`
	CallType string         `json:"callType"`
	Gas      hexutil.Big    `json:"gas"`
	Input    Data           `json:"input"`
	To       common.Address `json:"to"`
	Value    hexutil.Big    `json:"value"`
}

type CreateTraceAction struct {
	From  common.Address `json:"from"`
	Gas   hexutil.Big    `json:"gas"`
	Init  Data           `json:"init"`
	Value hexutil.Big    `json:"value"`
}

type SuicideTraceAction struct {
	Address       common.Address `json:"address"`
	RefundAddress common.Address `json:"refundAddress"`
	Balance       hexutil.Big    `json:"balance"`
}

type CreateTraceResult struct {
	// Do not change the ordering of these fields -- allows for easier comparison with other clients
	Address *common.Address `json:"address,omitempty"`
	Code    Data            `json:"code"`
	GasUsed *hexutil.Big    `json:"gasUsed"`
}

// TraceResult A parity formatted trace result
type TraceResult struct {
	// Do not change the ordering of these fields -- allows for easier comparison with other clients
	GasUsed *hexutil.Big `json:"gasUsed"`
	Output  Data         `json:"output"`
}

// Allows for easy printing of a parity trace for debugging
func (t ParityTrace) String() string {
	var ret string
	//ret += fmt.Sprintf("Action.SelfDestructed: %s\n", t.Action.SelfDestructed)
	//ret += fmt.Sprintf("Action.Balance: %s\n", t.Action.Balance)
	//ret += fmt.Sprintf("Action.CallType: %s\n", t.Action.CallType)
	//ret += fmt.Sprintf("Action.From: %s\n", t.Action.From)
	//ret += fmt.Sprintf("Action.Gas: %d\n", t.Action.Gas.ToInt())
	//ret += fmt.Sprintf("Action.Init: %s\n", t.Action.Init)
	//ret += fmt.Sprintf("Action.Input: %s\n", t.Action.Input)
	//ret += fmt.Sprintf("Action.RefundAddress: %s\n", t.Action.RefundAddress)
	//ret += fmt.Sprintf("Action.To: %s\n", t.Action.To)
	//ret += fmt.Sprintf("Action.Value: %s\n", t.Action.Value)
	ret += fmt.Sprintf("BlockHash: %v\n", t.BlockHash)
	ret += fmt.Sprintf("BlockNumber: %d\n", t.BlockNumber)
	//ret += fmt.Sprintf("Result.Address: %s\n", t.Result.Address)
	//ret += fmt.Sprintf("Result.Code: %s\n", t.Result.Code)
	//ret += fmt.Sprintf("Result.GasUsed: %s\n", t.Result.GasUsed)
	//ret += fmt.Sprintf("Result.Output: %s\n", t.Result.Output)
	ret += fmt.Sprintf("Subtraces: %d\n", t.Subtraces)
	ret += fmt.Sprintf("TraceAddress: %v\n", t.TraceAddress)
	ret += fmt.Sprintf("TransactionHash: %v\n", t.TransactionHash)
	ret += fmt.Sprintf("TransactionPosition: %d\n", t.TransactionPosition)
	ret += fmt.Sprintf("Type: %s\n", t.Type)
	return ret
}
