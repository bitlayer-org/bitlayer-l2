// Copyright 2023 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package tracers

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rpc"
)

type TraceAPI struct {
	backend          Backend
	traceFilterCount uint64
}

func NewTraceAPI(backend Backend, traceFilterCount uint64) *TraceAPI {
	log.Info("NewTraceAPI traceFilterCount", traceFilterCount)
	return &TraceAPI{backend: backend, traceFilterCount: traceFilterCount}
}

func (api *TraceAPI) Filter(ctx context.Context, req *types.TraceFilterRequest) (types.ParityTraces, error) {
	var fromBlock uint64
	var toBlock uint64
	if req.FromBlock == nil {
		fromBlock = 0
	} else {
		fromBlock = uint64(*req.FromBlock)
	}

	if req.ToBlock == nil {
		header, err := api.backend.HeaderByNumber(ctx, rpc.LatestBlockNumber)
		if err != nil {
			return nil, err
		}
		toBlock = header.Number.Uint64()
	} else {
		toBlock = uint64(*req.ToBlock)
	}
	if fromBlock > toBlock {
		return nil, errors.New("invalid parameters: fromBlock cannot be greater than toBlock")
	}

	fromAddresses := make(map[common.Address]struct{})
	for i := 0; i < len(req.FromAddress); i++ {
		fromAddresses[req.FromAddress[i]] = struct{}{}
	}
	toAddresses := make(map[common.Address]struct{})
	for i := 0; i < len(req.ToAddress); i++ {
		toAddresses[req.ToAddress[i]] = struct{}{}
	}

	includeAll := len(fromAddresses) == 0 && len(toAddresses) == 0

	// count := uint64(^uint(0)) // this just makes it easier to use below
	count := api.traceFilterCount
	if req.Count != nil {
		count = *req.Count
	}
	after := uint64(0) // this just makes it easier to use below
	if req.After != nil {
		after = *req.After
	}
	nSeen := uint64(0)
	nExported := uint64(0)

	traces := make([]types.ParityTrace, 0)
	for blockNumber := fromBlock; blockNumber <= toBlock; blockNumber++ {
		block, err := api.backend.BlockByNumber(ctx, rpc.BlockNumber(blockNumber))
		if err != nil {
			return nil, err
		}
		if block == nil {
			return nil, fmt.Errorf("block %#x not found", blockNumber)
		}
		txs := rawdb.ReadInternalTxs(api.backend.ChainDb(), block.Hash(), block.NumberU64())

		for i := 0; i < len(txs); i++ {
			tx := txs[i]
			for j := 0; j < len(tx.Actions); j++ {
				action := tx.Actions[j]
				skip := false
				if !includeAll {
					// TODO req.mode
					_, includeFrom := fromAddresses[action.From]
					_, includeTo := toAddresses[action.To]
					if !includeFrom && !includeTo {
						skip = true
					}
				}

				if skip {
					continue
				}

				nSeen++
				if nSeen > after && nExported < count {
					nExported++

					blockTxs := block.Transactions()
					blockHash := block.Hash()
					txHash := tx.TxHash
					var txPosition uint64 = 0
					for k := 0; k < blockTxs.Len(); k++ {
						if blockTxs[k].Hash() == txHash {
							txPosition = uint64(k)
							break
						}
					}
					subtraces := 0
					for k := 0; k < len(tx.Actions); k++ {
						if tx.Actions[k].Depth > action.Depth {
							subtraces++
						}
					}
					trace := types.ParityTrace{
						BlockHash:           &blockHash,
						BlockNumber:         &blockNumber,
						Error:               action.Error,
						Subtraces:           subtraces,
						TraceAddress:        action.TraceAddress,
						TransactionHash:     &txHash,
						TransactionPosition: &txPosition,
					}

					value := (*hexutil.Big)(action.Value)
					gas := (*hexutil.Big)(new(big.Int).SetUint64(action.Gas))
					gasUsed := (*hexutil.Big)(new(big.Int).SetUint64(action.GasUsed))
					if action.OpCode == "SELFDESTRUCT" {
						trace.Type = "suicide"
						trace.Action = types.SuicideTraceAction{
							Address:       action.From,
							RefundAddress: action.To,
							Balance:       *value,
						}
						trace.Result = types.TraceResult{
							GasUsed: gasUsed,
							Output:  action.Output,
						}
					} else if action.OpCode == "CREATE" || action.OpCode == "CREATE2" {
						trace.Type = "create"
						trace.Action = types.CreateTraceAction{
							From:  action.From,
							Gas:   *gas,
							Init:  action.Input,
							Value: *value,
						}
						trace.Result = types.CreateTraceResult{
							Address: &action.CreateAddress,
							Code:    action.Output,
							GasUsed: gasUsed,
						}
					} else {
						trace.Type = "call"
						trace.Action = types.CallTraceAction{
							From:     action.From,
							CallType: strings.ToLower(action.OpCode),
							Gas:      *gas,
							Input:    action.Input,
							To:       action.To,
							Value:    *value,
						}
						trace.Result = types.TraceResult{
							GasUsed: gasUsed,
							Output:  action.Output,
						}
					}
					traces = append(traces, trace)
				}

				if nExported >= count {
					return traces, nil
				}
			}
		}
	}
	return traces, nil
}

// TraceAPIs return the collection of RPC services the tracer package offers.
func TraceAPIs(backend Backend, traceFilterCount uint64) []rpc.API {
	// Append all the local APIs and return
	return []rpc.API{
		{
			Namespace: "trace",
			Service:   NewTraceAPI(backend, traceFilterCount),
		},
	}
}
