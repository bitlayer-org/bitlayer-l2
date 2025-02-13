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
	"crypto/ecdsa"
	"math/big"
	"math/rand"
	"sort"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/core/txpool"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

func TestTransactionPriceNonceSortLegacy(t *testing.T) {
	t.Parallel()
	testTransactionPriceNonceSort(t, nil)
}

func TestTransactionPriceNonceSort1559(t *testing.T) {
	t.Parallel()
	testTransactionPriceNonceSort(t, big.NewInt(0))
	testTransactionPriceNonceSort(t, big.NewInt(5))
	testTransactionPriceNonceSort(t, big.NewInt(50))
}

// Tests that transactions can be correctly sorted according to their price in
// decreasing order, but at the same time with increasing nonces when issued by
// the same account.
func testTransactionPriceNonceSort(t *testing.T, baseFee *big.Int) {
	// Generate a batch of accounts to start with
	keys := make([]*ecdsa.PrivateKey, 25)
	for i := 0; i < len(keys); i++ {
		keys[i], _ = crypto.GenerateKey()
	}
	signer := types.LatestSignerForChainID(common.Big1)

	// Generate a batch of transactions with overlapping values, but shifted nonces
	groups := map[common.Address][]*txpool.LazyTransaction{}
	expectedCount := 0
	for start, key := range keys {
		addr := crypto.PubkeyToAddress(key.PublicKey)
		count := 25
		for i := 0; i < 25; i++ {
			var tx *types.Transaction
			gasFeeCap := rand.Intn(50)
			if baseFee == nil {
				tx = types.NewTx(&types.LegacyTx{
					Nonce:    uint64(start + i),
					To:       &common.Address{},
					Value:    big.NewInt(100),
					Gas:      100,
					GasPrice: big.NewInt(int64(gasFeeCap)),
					Data:     nil,
				})
			} else {
				tx = types.NewTx(&types.DynamicFeeTx{
					Nonce:     uint64(start + i),
					To:        &common.Address{},
					Value:     big.NewInt(100),
					Gas:       100,
					GasFeeCap: big.NewInt(int64(gasFeeCap)),
					GasTipCap: big.NewInt(int64(rand.Intn(gasFeeCap + 1))),
					Data:      nil,
				})
				if count == 25 && int64(gasFeeCap) < baseFee.Int64() {
					count = i
				}
			}
			tx, err := types.SignTx(tx, signer, key)
			if err != nil {
				t.Fatalf("failed to sign tx: %s", err)
			}
			groups[addr] = append(groups[addr], &txpool.LazyTransaction{
				Hash:      tx.Hash(),
				Tx:        tx,
				Time:      tx.Time(),
				GasFeeCap: tx.GasFeeCap(),
				GasTipCap: tx.GasTipCap(),
				Gas:       tx.Gas(),
				BlobGas:   tx.BlobGas(),
			})
		}
		expectedCount += count
	}
	// Sort the transactions and cross check the nonce ordering
	// txset := newTransactionsByPriceAndNonce(signer, groups, baseFee)
	txset := NewTransactionsByPriceAndNonce(0, signer, groups, baseFee, nil)

	txs := types.Transactions{}
	for tx := txset.Peek(); tx != nil; tx = txset.Peek() {
		fromi, _ := types.Sender(signer, tx.Tx)
		println("traverse ", fromi.Hex(), tx.Tx.GasTipCap().String())
		txs = append(txs, tx.Tx)
		txset.Shift()
	}
	if len(txs) != expectedCount {
		t.Errorf("expected %d transactions, found %d", expectedCount, len(txs))
	}
	for i, txi := range txs {
		fromi, _ := types.Sender(signer, txi)

		// Make sure the nonce order is valid
		for j, txj := range txs[i+1:] {
			fromj, _ := types.Sender(signer, txj)
			if fromi == fromj && txi.Nonce() > txj.Nonce() {
				t.Errorf("invalid nonce ordering: tx #%d (A=%x N=%v) < tx #%d (A=%x N=%v)", i, fromi[:4], txi.Nonce(), i+j, fromj[:4], txj.Nonce())
			}
		}
		// If the next tx has different from account, the price must be lower than the current one
		if i+1 < len(txs) {
			next := txs[i+1]
			fromNext, _ := types.Sender(signer, next)
			tip, err := txi.EffectiveGasTip(baseFee)
			nextTip, nextErr := next.EffectiveGasTip(baseFee)
			if err != nil || nextErr != nil {
				t.Errorf("error calculating effective tip: %v, %v", err, nextErr)
			}
			if fromi != fromNext && tip.Cmp(nextTip) < 0 {
				t.Errorf("invalid gasprice ordering: tx #%d (A=%x P=%v) < tx #%d (A=%x P=%v)", i, fromi[:4], txi.GasPrice(), i+1, fromNext[:4], next.GasPrice())
			}
		}
	}
}

// Tests that if multiple transactions have the same price, the ones seen earlier
// are prioritized to avoid network spam attacks aiming for a specific ordering.
func TestTransactionTimeSort(t *testing.T) {
	t.Parallel()
	// Generate a batch of accounts to start with
	keys := make([]*ecdsa.PrivateKey, 5)
	for i := 0; i < len(keys); i++ {
		keys[i], _ = crypto.GenerateKey()
	}
	signer := types.HomesteadSigner{}

	// Generate a batch of transactions with overlapping prices, but different creation times
	groups := map[common.Address][]*txpool.LazyTransaction{}
	for start, key := range keys {
		addr := crypto.PubkeyToAddress(key.PublicKey)

		tx, _ := types.SignTx(types.NewTransaction(0, common.Address{}, big.NewInt(100), 100, big.NewInt(1), nil), signer, key)
		tx.SetTime(time.Unix(0, int64(len(keys)-start)))

		groups[addr] = append(groups[addr], &txpool.LazyTransaction{
			Hash:      tx.Hash(),
			Tx:        tx,
			Time:      tx.Time(),
			GasFeeCap: tx.GasFeeCap(),
			GasTipCap: tx.GasTipCap(),
			Gas:       tx.Gas(),
			BlobGas:   tx.BlobGas(),
		})
	}
	// Sort the transactions and cross check the nonce ordering
	// txset := newTransactionsByPriceAndNonce(signer, groups, nil)
	txset := NewTransactionsByPriceAndNonce(2, signer, groups, nil, nil)

	txs := types.Transactions{}
	for tx := txset.Peek(); tx != nil; tx = txset.Peek() {
		txs = append(txs, tx.Tx)
		txset.Shift()
	}
	if len(txs) != len(keys) {
		t.Errorf("expected %d transactions, found %d", len(keys), len(txs))
	}
	for i, txi := range txs {
		fromi, _ := types.Sender(signer, txi)
		if i+1 < len(txs) {
			next := txs[i+1]
			fromNext, _ := types.Sender(signer, next)

			if txi.GasPrice().Cmp(next.GasPrice()) < 0 {
				t.Errorf("invalid gasprice ordering: tx #%d (A=%x P=%v) < tx #%d (A=%x P=%v)", i, fromi[:4], txi.GasPrice(), i+1, fromNext[:4], next.GasPrice())
			}
			// Make sure time order is ascending if the txs have the same gas price
			if txi.GasPrice().Cmp(next.GasPrice()) == 0 && txi.Time().After(next.Time()) {
				t.Errorf("invalid received time ordering: tx #%d (A=%x T=%v) > tx #%d (A=%x T=%v)", i, fromi[:4], txi.Time(), i+1, fromNext[:4], next.Time())
			}
		}
	}
}

func TestTransactionPriceNonceSortLegacyPoll(t *testing.T) {
	t.Parallel()
	testTransactionPriceNonceSortPoll(t, nil)
}

func TestTransactionPriceNonceSort1559Poll(t *testing.T) {
	t.Parallel()
	testTransactionPriceNonceSortPoll(t, big.NewInt(0))
	testTransactionPriceNonceSortPoll(t, big.NewInt(5))
	testTransactionPriceNonceSortPoll(t, big.NewInt(50))
}

// Tests that transactions can be correctly sorted according to their price in
// decreasing order, but at the same time with increasing nonces when issued by
// the same account.
func testTransactionPriceNonceSortPoll(t *testing.T, baseFee *big.Int) {
	// Generate a batch of accounts to start with
	keys := make([]*ecdsa.PrivateKey, 25)
	for i := 0; i < len(keys); i++ {
		keys[i], _ = crypto.GenerateKey()
	}
	signer := types.LatestSignerForChainID(common.Big1)

	// Generate a batch of transactions with overlapping values, but shifted nonces
	groups := map[common.Address][]*txpool.LazyTransaction{}
	expectedCount := 0
	for start, key := range keys {
		addr := crypto.PubkeyToAddress(key.PublicKey)
		count := 25
		for i := 0; i < 25; i++ {
			var tx *types.Transaction
			gasTipCap := rand.Intn(50)
			gasFeeCap := rand.Intn(50) + 50
			if baseFee == nil {
				tx = types.NewTx(&types.LegacyTx{
					Nonce:    uint64(start + i),
					To:       &common.Address{},
					Value:    big.NewInt(100),
					Gas:      100,
					GasPrice: big.NewInt(int64(gasFeeCap)),
					Data:     nil,
				})
			} else {
				tx = types.NewTx(&types.DynamicFeeTx{
					Nonce:     uint64(start + i),
					To:        &common.Address{},
					Value:     big.NewInt(100),
					Gas:       100,
					GasFeeCap: big.NewInt(int64(gasFeeCap)),
					GasTipCap: big.NewInt(int64(rand.Intn(gasTipCap + 1))),
					Data:      nil,
				})
				if count == 25 && int64(gasFeeCap) < baseFee.Int64() {
					count = i
				}
			}
			tx, err := types.SignTx(tx, signer, key)
			if err != nil {
				t.Fatalf("failed to sign tx: %s", err)
			}
			groups[addr] = append(groups[addr], &txpool.LazyTransaction{
				Hash:      tx.Hash(),
				Tx:        tx,
				Time:      tx.Time(),
				GasFeeCap: tx.GasFeeCap(),
				GasTipCap: tx.GasTipCap(),
				Gas:       tx.Gas(),
				BlobGas:   tx.BlobGas(),
			})
		}
		expectedCount += count
	}
	// Sort the transactions and cross check the nonce ordering
	// txset := newTransactionsByPriceAndNonceAndPoll(signer, groups, baseFee)
	txset := NewTransactionsByPriceAndNonce(2, signer, groups, baseFee, nil)

	txs := types.Transactions{}
	for tx := txset.Peek(); tx != nil; tx = txset.Peek() {
		txs = append(txs, tx.Tx)
		txset.Shift()
	}
	if len(txs) != expectedCount {
		t.Errorf("expected %d transactions, found %d", expectedCount, len(txs))
	}

	for i, txi := range txs {
		fromi, _ := types.Sender(signer, txi)
		// Make sure the nonce order is valid
		for j, txj := range txs[i+1:] {
			fromj, _ := types.Sender(signer, txj)
			if fromi == fromj && txi.Nonce() > txj.Nonce() {
				t.Errorf("invalid nonce ordering: tx #%d (A=%x N=%v) < tx #%d (A=%x N=%v)", i, fromi[:4], txi.Nonce(), i+j, fromj[:4], txj.Nonce())
			}
		}
	}

	for i := 0; i < 25; i++ {
		fromi, _ := types.Sender(signer, txs[i])
		for j := 0; j < 25; j++ {
			fromexpected, _ := types.Sender(signer, txs[j*25+i])
			if fromi != fromexpected {
				t.Errorf(" from[%d] != from[%d*25+%d]", i, j, i)
			}
		}

		fromi2, _ := types.Sender(signer, txs[i*25])
		for k := 1; k < 25; k++ {
			fromexpected, _ := types.Sender(signer, txs[i*25+k])
			if fromi2 == fromexpected {
				t.Errorf(" from[i] == from[i+k]")
			}
		}
	}
}

func TestTransactionPriceNonceSortLegacyDiscount(t *testing.T) {
	t.Parallel()
	testTransactionPriceNonceSortDiscount(t, nil, big.NewInt(0), 0)
	testTransactionPriceNonceSortDiscount(t, nil, big.NewInt(0), 1)
	testTransactionPriceNonceSortDiscount(t, nil, big.NewInt(0), 2)
	testTransactionPriceNonceSortDiscount(t, nil, big.NewInt(0), 3)

	testTransactionPriceNonceSortDiscount(t, nil, big.NewInt(10), 0)
	testTransactionPriceNonceSortDiscount(t, nil, big.NewInt(10), 1)
	testTransactionPriceNonceSortDiscount(t, nil, big.NewInt(10), 2)
	testTransactionPriceNonceSortDiscount(t, nil, big.NewInt(10), 3)

	testTransactionPriceNonceSortDiscount(t, nil, big.NewInt(50), 0)
	testTransactionPriceNonceSortDiscount(t, nil, big.NewInt(50), 1)
	testTransactionPriceNonceSortDiscount(t, nil, big.NewInt(50), 2)
	testTransactionPriceNonceSortDiscount(t, nil, big.NewInt(50), 3)
}

func TestTransactionPriceNonceSort1559Discount(t *testing.T) {
	t.Parallel()
	testTransactionPriceNonceSortDiscount(t, big.NewInt(0), big.NewInt(0), 0)
	testTransactionPriceNonceSortDiscount(t, big.NewInt(0), big.NewInt(0), 1)
	testTransactionPriceNonceSortDiscount(t, big.NewInt(0), big.NewInt(0), 2)
	testTransactionPriceNonceSortDiscount(t, big.NewInt(0), big.NewInt(0), 3)

	testTransactionPriceNonceSortDiscount(t, big.NewInt(5), big.NewInt(10), 0)
	testTransactionPriceNonceSortDiscount(t, big.NewInt(5), big.NewInt(10), 1)
	testTransactionPriceNonceSortDiscount(t, big.NewInt(5), big.NewInt(10), 2)
	testTransactionPriceNonceSortDiscount(t, big.NewInt(5), big.NewInt(10), 3)

	testTransactionPriceNonceSortDiscount(t, big.NewInt(50), big.NewInt(20), 0)
	testTransactionPriceNonceSortDiscount(t, big.NewInt(50), big.NewInt(20), 1)
	testTransactionPriceNonceSortDiscount(t, big.NewInt(50), big.NewInt(20), 2)
	testTransactionPriceNonceSortDiscount(t, big.NewInt(50), big.NewInt(20), 3)

	testTransactionPriceNonceSortDiscount(t, big.NewInt(50), big.NewInt(30), 0)
	testTransactionPriceNonceSortDiscount(t, big.NewInt(50), big.NewInt(30), 1)
	testTransactionPriceNonceSortDiscount(t, big.NewInt(50), big.NewInt(30), 2)
	testTransactionPriceNonceSortDiscount(t, big.NewInt(50), big.NewInt(30), 3)
}

// Tests that transactions can be correctly sorted according to their price in
// decreasing order, but at the same time with increasing nonces when issued by
// the same account.
func testTransactionPriceNonceSortDiscount(t *testing.T, baseFee *big.Int, tip *big.Int, policy int) {
	// Generate a batch of accounts to start with
	keys := make([]*ecdsa.PrivateKey, 25)
	for i := 0; i < len(keys); i++ {
		keys[i], _ = crypto.GenerateKey()
	}
	signer := types.LatestSignerForChainID(common.Big1)

	// Generate a batch of transactions with overlapping values, but shifted nonces
	groups := map[common.Address][]*txpool.LazyTransaction{}
	expectedCount := 0
	for start, key := range keys {
		gasFeeCap := 100
		gastip := make([]int, 25)
		if policy == 0 {
			tiprang := int(tip.Int64()) // all tx.tip < mintip
			for i := 0; i < 25; i++ {
				if tiprang == 0 {
					gastip[i] = 100
				} else {
					gastip[i] = rand.Intn(tiprang)
				}
			}
		} else if policy == 1 {
			tiprang := int(tip.Int64()) // all tx.tip > mintip
			for i := 0; i < 25; i++ {
				if tiprang == 0 {
					gastip[i] = 100
				} else {
					gastip[i] = rand.Intn(tiprang) + int(tip.Int64())
				}
			}
		} else if policy == 2 {
			tiprang := gasFeeCap
			if baseFee != nil {
				tiprang = gasFeeCap - int(baseFee.Int64()) // all tx.tip = random(feecap-basefee)
			}
			for i := 0; i < 25; i++ {
				if tiprang == 0 {
					gastip[i] = 100
				} else {
					gastip[i] = rand.Intn(tiprang)
				}
			}
		} else { // if policy ==3
			if start%2 == 0 {
				tiprang := gasFeeCap
				if baseFee != nil {
					tiprang = gasFeeCap - int(baseFee.Int64()) // all tx.tip = random(feecap-basefee)
				}
				for i := 0; i < 25; i++ {
					if tiprang == 0 {
						gastip[i] = 100
					} else {
						gastip[i] = rand.Intn(tiprang)
					}
				}
			} else {
				tiprang := int(tip.Int64()) // all tx.tip < mintip
				for i := 0; i < 25; i++ {
					if tiprang == 0 {
						gastip[i] = 100
					} else {
						gastip[i] = rand.Intn(tiprang)
					}
				}
			}
		}

		sort.Ints(gastip)
		sort.Sort(sort.Reverse(sort.IntSlice(gastip)))

		addr := crypto.PubkeyToAddress(key.PublicKey)
		count := 25
		for i := 0; i < 25; i++ {
			var tx *types.Transaction

			if baseFee == nil {
				tx = types.NewTx(&types.LegacyTx{
					Nonce:    uint64(start + i),
					To:       &common.Address{},
					Value:    big.NewInt(100),
					Gas:      uint64(gastip[i]), //100,
					GasPrice: big.NewInt(int64(gastip[i])),
					Data:     nil,
				})
			} else {
				tx = types.NewTx(&types.DynamicFeeTx{
					Nonce:     uint64(start + i),
					To:        &common.Address{},
					Value:     big.NewInt(100),
					Gas:       uint64(gasFeeCap),
					GasFeeCap: big.NewInt(int64(gasFeeCap)),
					GasTipCap: big.NewInt(int64(gastip[i])),
					Data:      nil,
				})
				if count == 25 && int64(gasFeeCap) < baseFee.Int64() {
					count = i
				}
			}
			tx, err := types.SignTx(tx, signer, key)
			if err != nil {
				t.Fatalf("failed to sign tx: %s", err)
			}
			groups[addr] = append(groups[addr], &txpool.LazyTransaction{
				Hash:      tx.Hash(),
				Tx:        tx,
				Time:      tx.Time(),
				GasFeeCap: tx.GasFeeCap(),
				GasTipCap: tx.GasTipCap(),
				Gas:       tx.Gas(),
				BlobGas:   tx.BlobGas(),
			})
		}
		expectedCount += count
	}
	// Sort the transactions and cross check the nonce ordering
	// txset := newTransactionsByPriceAndNonceAndDiscount(signer, groups, baseFee, tip)
	txset := NewTransactionsByPriceAndNonce(1, signer, groups, baseFee, tip)

	txs := types.Transactions{}
	for tx := txset.Peek(); tx != nil; tx = txset.Peek() {
		fromi, _ := types.Sender(signer, tx.Tx)
		println("traverse ", fromi.Hex(), tx.Tx.GasTipCap().String(), tx.Tx.Nonce())
		txs = append(txs, tx.Tx)
		txset.Shift()
	}
	if len(txs) != expectedCount {
		t.Errorf("expected %d transactions, found %d", expectedCount, len(txs))
	}
	addrm := make(map[string]int)
	for i, txi := range txs {
		fromi, _ := types.Sender(signer, txi)
		addrm[fromi.Hex()] = addrm[fromi.Hex()] + 1

		// Make sure the nonce order is valid
		for j, txj := range txs[i+1:] {
			fromj, _ := types.Sender(signer, txj)
			if fromi == fromj {
				// nonce asc
				if txi.Nonce() > txj.Nonce() {
					t.Errorf("invalid nonce ordering: tx #%d (A=%x N=%v) < tx #%d (A=%x N=%v)", i, fromi[:4], txi.Nonce(), i+j, fromj[:4], txj.Nonce())
				}
				tipi := new(big.Int).Set(txi.GasTipCap())
				if baseFee != nil {
					tipi = math.BigMin(txi.GasTipCap(), new(big.Int).Sub(txi.GasFeeCap(), baseFee))
				}
				tipj := new(big.Int).Set(txj.GasTipCap())
				if baseFee != nil {
					tipj = math.BigMin(txj.GasTipCap(), new(big.Int).Sub(txj.GasFeeCap(), baseFee))
				}
				if tipi.Cmp(tipj) < 0 {
					t.Errorf("invalid tip ordering: tx #%d (A=%x N=%v t=%v) < tx #%d (A=%x N=%v t=%v)", i, fromi[:4], txi.Nonce(), tipi, i+j, fromj[:4], txj.Nonce(), tipj)
				}
			}
		}
	}
	for k, v := range addrm {
		if v != 25 {
			t.Errorf("addr %s tx count %d != 25", k, v)
		}
	}
}
