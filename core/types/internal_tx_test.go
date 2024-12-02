package types

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/stretchr/testify/assert"
)

func TestInternalTx(t *testing.T) {
	legacy := &ActionLegacy{
		From:         common.Address{},
		To:           common.Address{},
		Value:        big.NewInt(1),
		Success:      true,
		OpCode:       "CALL",
		Depth:        10,
		Gas:          2,
		GasUsed:      1,
		Input:        make([]byte, 0),
		Output:       make([]byte, 0),
		TraceAddress: make([]uint64, 0),
		Error:        "test",
	}
	action := &Action{
		From:          common.Address{},
		To:            common.Address{},
		CreateAddress: common.Address{},
		Value:         big.NewInt(0),
		Success:       true,
		OpCode:        "CALL",
		Depth:         0,
		Gas:           0,
		GasUsed:       0,
		Input:         make([]byte, 0),
		Output:        make([]byte, 0),
		TraceAddress:  make([]uint64, 0),
		Error:         "",
	}

	lb, err := rlp.EncodeToBytes(legacy)
	if err != nil {
		t.Errorf("rlp.encode legacy %s", err.Error())
	}
	la, err := rlp.EncodeToBytes(action)
	if err != nil {
		t.Errorf("rlp.encode action %s", err.Error())
	}

	var dl ActionLegacy
	err = rlp.DecodeBytes(lb, &dl)
	if err != nil {
		t.Errorf("rlp.decode legacy %s", err.Error())
	}
	var da Action
	err = rlp.DecodeBytes(la, &da)
	if err != nil {
		t.Errorf("rlp.decode action %s", err.Error())
	}

	var dla ActionLegacy
	err = rlp.DecodeBytes(la, &dla)
	if err != nil {
		t.Log("rlp.decode legacy with action", err.Error())

		var dat Action
		err = rlp.DecodeBytes(la, &dat)
		if err != nil {
			t.Errorf("rlp.decode try action %s", err.Error())
		}
	}
	var dal Action
	err = rlp.DecodeBytes(lb, &dal)
	if err != nil {
		t.Log("rlp.decode action with legacy", err.Error())
		var dlt ActionLegacy
		err = rlp.DecodeBytes(lb, &dlt)
		if err != nil {
			t.Log("rlp.decode try legacy", err.Error())
			t.Errorf("rlp.decode try legacy %s", err.Error())
		}
	}

	legacys := make([]*ActionLegacy, 0)
	legacys = append(legacys, legacy)
	internalTxLegacy := &InternalTxLegacy{
		TxHash:      common.Hash{},
		BlockHash:   common.Hash{},
		BlockNumber: big.NewInt(0),
		Actions:     legacys,
	}
	internalTxsLegacy := make([]*InternalTxLegacy, 0)
	internalTxsLegacy = append(internalTxsLegacy, internalTxLegacy)
	txs := NewInternalTxsByLegacy(internalTxsLegacy)
	if len(txs) != len(internalTxsLegacy) {
		t.Errorf("convert legacy actions error, lenth not equal ")
	}
	assert := assert.New(t)
	for i := 0; i < len(txs); i++ {
		assert.Equal(txs[i].TxHash, internalTxsLegacy[i].BlockHash)
		assert.Equal(txs[i].BlockHash, internalTxsLegacy[i].BlockHash)
		assert.Equal(txs[i].BlockNumber, internalTxsLegacy[i].BlockNumber)
		assert.Equal(len(txs[i].Actions), len(internalTxsLegacy[i].Actions))
		for j := 0; j < len(txs[i].Actions); j++ {
			assert.Equal(txs[i].Actions[j].CreateAddress, common.Address{})
			assert.Equal(txs[i].Actions[j].From, internalTxsLegacy[i].Actions[j].From)
			assert.Equal(txs[i].Actions[j].To, internalTxsLegacy[i].Actions[j].To)
			assert.Equal(txs[i].Actions[j].Value, internalTxsLegacy[i].Actions[j].Value)
			assert.Equal(txs[i].Actions[j].Success, internalTxsLegacy[i].Actions[j].Success)
			assert.Equal(txs[i].Actions[j].OpCode, internalTxsLegacy[i].Actions[j].OpCode)
			assert.Equal(txs[i].Actions[j].Depth, internalTxsLegacy[i].Actions[j].Depth)
			assert.Equal(txs[i].Actions[j].Gas, internalTxsLegacy[i].Actions[j].Gas)
			assert.Equal(txs[i].Actions[j].GasUsed, internalTxsLegacy[i].Actions[j].GasUsed)
			assert.Equal(txs[i].Actions[j].Input, internalTxsLegacy[i].Actions[j].Input)
			assert.Equal(txs[i].Actions[j].Output, internalTxsLegacy[i].Actions[j].Output)
			assert.Equal(txs[i].Actions[j].TraceAddress, internalTxsLegacy[i].Actions[j].TraceAddress)
			assert.Equal(txs[i].Actions[j].Error, internalTxsLegacy[i].Actions[j].Error)
		}
	}
}
