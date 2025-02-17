// Copyright 2014 The go-ethereum Authors
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

package miner

import (
	"container/heap"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/core/txpool"
	"github.com/ethereum/go-ethereum/core/types"
)

// txWithMinerFee wraps a transaction with its gas price or effective miner gasTipCap
type txWithMinerFee struct {
	tx   *txpool.LazyTransaction
	from common.Address
	fees *big.Int
}

// newTxWithMinerFee creates a wrapped transaction, calculating the effective
// miner gasTipCap if a base fee is provided.
// Returns error in case of a negative effective miner gasTipCap.
func newTxWithMinerFee(tx *txpool.LazyTransaction, from common.Address, baseFee *big.Int) (*txWithMinerFee, error) {
	tip := new(big.Int).Set(tx.GasTipCap)
	if baseFee != nil {
		if tx.GasFeeCap.Cmp(baseFee) < 0 {
			return nil, types.ErrGasFeeCapTooLow
		}
		tip = math.BigMin(tx.GasTipCap, new(big.Int).Sub(tx.GasFeeCap, baseFee))
	}
	return &txWithMinerFee{
		tx:   tx,
		from: from,
		fees: tip,
	}, nil
}

// txByPriceAndTime implements both the sort and the heap interface, making it useful
// for all at once sorting as well as individually adding and removing elements.
type txByPriceAndTime []*txWithMinerFee

func (s txByPriceAndTime) Len() int { return len(s) }
func (s txByPriceAndTime) Less(i, j int) bool {
	// If the prices are equal, use the time the transaction was first seen for
	// deterministic sorting
	cmp := s[i].fees.Cmp(s[j].fees)
	if cmp == 0 {
		return s[i].tx.Time.Before(s[j].tx.Time)
	}
	return cmp > 0
}
func (s txByPriceAndTime) Swap(i, j int) { s[i], s[j] = s[j], s[i] }

func (s *txByPriceAndTime) Push(x interface{}) {
	*s = append(*s, x.(*txWithMinerFee))
}

func (s *txByPriceAndTime) Pop() interface{} {
	old := *s
	n := len(old)
	x := old[n-1]
	old[n-1] = nil
	*s = old[0 : n-1]
	return x
}

type transactionsByPriceAndNonce interface {
	Peek() *txpool.LazyTransaction
	Shift()
	Pop()
}

func NewTransactionsByPriceAndNonce(policy uint8, signer types.Signer, txs map[common.Address][]*txpool.LazyTransaction, baseFee *big.Int, tip *big.Int) transactionsByPriceAndNonce {
	if policy == 0 {
		return newTransactionsByPriceAndNonceAndDiscount(signer, txs, baseFee, tip)
	} else if policy == 1 {
		return newTransactionsByPriceAndNonceAndPoll(signer, txs, baseFee)
	} else {
		return newTransactionsByPriceAndNonceLegacy(signer, txs, baseFee)
	}
}

// transactionsByPriceAndNonce represents a set of transactions that can return
// transactions in a profit-maximizing sorted order, while supporting removing
// entire batches of transactions for non-executable accounts.
type transactionsByPriceAndNonceLegacy struct {
	txs     map[common.Address][]*txpool.LazyTransaction // Per account nonce-sorted list of transactions
	heads   txByPriceAndTime                             // Next transaction for each unique account (price heap)
	signer  types.Signer                                 // Signer for the set of transactions
	baseFee *big.Int                                     // Current base fee
}

// newTransactionsByPriceAndNonce creates a transaction set that can retrieve
// price sorted transactions in a nonce-honouring way.
//
// Note, the input map is reowned so the caller should not interact any more with
// if after providing it to the constructor.
func newTransactionsByPriceAndNonceLegacy(signer types.Signer, txs map[common.Address][]*txpool.LazyTransaction, baseFee *big.Int) *transactionsByPriceAndNonceLegacy {
	// Initialize a price and received time based heap with the head transactions
	heads := make(txByPriceAndTime, 0, len(txs))
	for from, accTxs := range txs {
		wrapped, err := newTxWithMinerFee(accTxs[0], from, baseFee)
		if err != nil {
			delete(txs, from)
			continue
		}
		heads = append(heads, wrapped)
		txs[from] = accTxs[1:]
	}
	heap.Init(&heads)

	// Assemble and return the transaction set
	return &transactionsByPriceAndNonceLegacy{
		txs:     txs,
		heads:   heads,
		signer:  signer,
		baseFee: baseFee,
	}
}

// Peek returns the next transaction by price.
func (t *transactionsByPriceAndNonceLegacy) Peek() *txpool.LazyTransaction {
	if len(t.heads) == 0 {
		return nil
	}
	return t.heads[0].tx
}

// Shift replaces the current best head with the next one from the same account.
func (t *transactionsByPriceAndNonceLegacy) Shift() {
	acc := t.heads[0].from
	if txs, ok := t.txs[acc]; ok && len(txs) > 0 {
		if wrapped, err := newTxWithMinerFee(txs[0], acc, t.baseFee); err == nil {
			t.heads[0], t.txs[acc] = wrapped, txs[1:]
			heap.Fix(&t.heads, 0)
			return
		}
	}
	heap.Pop(&t.heads)
}

// Pop removes the best transaction, *not* replacing it with the next one from
// the same account. This should be used when a transaction cannot be executed
// and hence all subsequent ones should be discarded from the same account.
func (t *transactionsByPriceAndNonceLegacy) Pop() {
	heap.Pop(&t.heads)
}

// transactionsByPriceAndNonce represents a set of transactions that can return
// transactions in a profit-maximizing sorted order, while supporting removing
// entire batches of transactions for non-executable accounts.
type transactionsByPriceAndNonceAndPoll struct {
	txs     map[common.Address][]*txpool.LazyTransaction // Per account nonce-sorted list of transactions
	heads   txByPriceAndTime                             // Next transaction for each unique account (price heap)
	signer  types.Signer                                 // Signer for the set of transactions
	baseFee *big.Int                                     // Current base fee
}

// newTransactionsByPriceAndNonce creates a transaction set that can retrieve
// price sorted transactions in a nonce-honouring way.
//
// Note, the input map is reowned so the caller should not interact any more with
// if after providing it to the constructor.
func newTransactionsByPriceAndNonceAndPoll(signer types.Signer, txs map[common.Address][]*txpool.LazyTransaction, baseFee *big.Int) *transactionsByPriceAndNonceAndPoll {
	// Initialize a price and received time based heap with the head transactions
	heads := make(txByPriceAndTime, 0, len(txs))
	for from, accTxs := range txs {
		wrapped, err := newTxWithMinerFee(accTxs[0], from, baseFee)
		if err != nil {
			delete(txs, from)
			continue
		}
		heads = append(heads, wrapped)
		txs[from] = accTxs[1:]
	}
	// heap.Init(&heads)

	// Assemble and return the transaction set
	return &transactionsByPriceAndNonceAndPoll{
		txs:     txs,
		heads:   heads,
		signer:  signer,
		baseFee: baseFee,
	}
}

// Peek returns the next transaction by price.
func (t *transactionsByPriceAndNonceAndPoll) Peek() *txpool.LazyTransaction {
	if len(t.heads) == 0 {
		return nil
	}
	return t.heads[0].tx
}

// Shift replaces the current best head with the next one from the same account.
func (t *transactionsByPriceAndNonceAndPoll) Shift() {
	acc := t.heads[0].from
	if txs, ok := t.txs[acc]; ok && len(txs) > 0 {
		if wrapped, err := newTxWithMinerFee(txs[0], acc, t.baseFee); err == nil {
			// t.heads[0], t.txs[acc] = wrapped, txs[1:]
			// heap.Fix(&t.heads, 0)
			// return
			t.txs[acc] = txs[1:]
			t.heads = append(t.heads, wrapped)
			t.heads = t.heads[1:]
			return
		}
	}
	// heap.Pop(&t.heads)
	t.Pop()
}

// Pop removes the best transaction, *not* replacing it with the next one from
// the same account. This should be used when a transaction cannot be executed
// and hence all subsequent ones should be discarded from the same account.
func (t *transactionsByPriceAndNonceAndPoll) Pop() {
	// heap.Pop(&t.heads)
	if len(t.heads) > 0 {
		t.heads = t.heads[1:]
	}
}

// transactionsByPriceAndNonce represents a set of transactions that can return
// transactions in a profit-maximizing sorted order, while supporting removing
// entire batches of transactions for non-executable accounts.
type transactionsByPriceAndNoncAndDiscount struct {
	txs            map[common.Address][]*txpool.LazyTransaction // Per account nonce-sorted list of transactions
	heads          txByPriceAndTime                             // Next transaction for each unique account (price heap)
	heads_discount txByPriceAndTime
	signer         types.Signer // Signer for the set of transactions
	baseFee        *big.Int     // Current base fee
	is_heads       bool
	tip            *big.Int
}

// newTransactionsByPriceAndNonce creates a transaction set that can retrieve
// price sorted transactions in a nonce-honouring way.
//
// Note, the input map is reowned so the caller should not interact any more with
// if after providing it to the constructor.
func newTransactionsByPriceAndNonceAndDiscount(signer types.Signer, txs map[common.Address][]*txpool.LazyTransaction, baseFee *big.Int, tip *big.Int) *transactionsByPriceAndNoncAndDiscount {
	// Initialize a price and received time based heap with the head transactions
	heads := make(txByPriceAndTime, 0)
	heads_discount := make(txByPriceAndTime, 0)

	for from, accTxs := range txs {
		wrapped, err := newTxWithMinerFee(accTxs[0], from, baseFee)
		if err != nil {
			delete(txs, from)
			continue
		}
		// heads = append(heads, wrapped)
		if wrapped.fees.Cmp(tip) >= 0 { // wrapped.fee >= tip
			heads = append(heads, wrapped)
		} else {
			heads_discount = append(heads_discount, wrapped)
		}
		txs[from] = accTxs[1:]
	}

	heap.Init(&heads)
	heap.Init(&heads_discount)

	is_heads := true
	if len(heads) > 0 {
		is_heads = true
	} else {
		if len(heads_discount) > 0 {
			is_heads = false
		}
	}

	// Assemble and return the transaction set
	return &transactionsByPriceAndNoncAndDiscount{
		txs:            txs,
		heads:          heads,
		heads_discount: heads_discount,
		signer:         signer,
		baseFee:        baseFee,
		is_heads:       is_heads,
		tip:            tip,
	}
}

// Peek returns the next transaction by price.
func (t *transactionsByPriceAndNoncAndDiscount) Peek() *txpool.LazyTransaction {
	// if len(t.heads) == 0 {
	// 	return nil
	// }
	// return t.heads[0].tx
	if len(t.heads) == 0 && len(t.heads_discount) == 0 {
		return nil
	}
	if t.is_heads {
		if len(t.heads) == 0 {
			t.is_heads = false
		}
	} else {
		if len(t.heads_discount) == 0 {
			t.is_heads = true
		}
	}

	if t.is_heads {
		return t.heads[0].tx
	} else {
		return t.heads_discount[0].tx
	}
}

// Shift replaces the current best head with the next one from the same account.
func (t *transactionsByPriceAndNoncAndDiscount) Shift() {
	// acc := t.heads[0].from
	var acc common.Address
	if t.is_heads {
		acc = t.heads[0].from
	} else {
		acc = t.heads_discount[0].from
	}
	if txs, ok := t.txs[acc]; ok && len(txs) > 0 {
		if wrapped, err := newTxWithMinerFee(txs[0], acc, t.baseFee); err == nil {
			// t.heads[0], t.txs[acc] = wrapped, txs[1:]
			// heap.Fix(&t.heads, 0)
			// return
			t.txs[acc] = txs[1:]
			t.Pop()
			if wrapped.fees.Cmp(t.tip) >= 0 { // wrapped.fee >= tip
				heap.Push(&t.heads, wrapped)
			} else {
				heap.Push(&t.heads_discount, wrapped)
			}
			return
		}
	}
	// heap.Pop(&t.heads)
	t.Pop()
}

// Pop removes the best transaction, *not* replacing it with the next one from
// the same account. This should be used when a transaction cannot be executed
// and hence all subsequent ones should be discarded from the same account.
func (t *transactionsByPriceAndNoncAndDiscount) Pop() {
	// heap.Pop(&t.heads)
	if t.is_heads {
		heap.Pop(&t.heads)
	} else {
		heap.Pop(&t.heads_discount)
	}
	t.is_heads = !t.is_heads
}
