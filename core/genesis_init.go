// Copyright 2021 The Cube Authors
// This file is part of the Cube library.
//
// The Cube library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The Cube library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the Cube library. If not, see <http://www.gnu.org/licenses/>.

package core

import (
	"errors"
	"fmt"
	"math"
	"math/big"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/contracts/system"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
)

const (
	initBatch   = 30
	extraVanity = 32                     // Fixed number of extra-data prefix bytes reserved for validator vanity
	extraSeal   = crypto.SignatureLength // Fixed number of extra-data suffix bytes reserved for validator seal
)

var (
	EngineCaller = common.HexToAddress("0x0000000000004269746c61796572456e67696e65")
)

// // fromGwei convert amount from gwei to wei
// func fromGwei(gwei int64) *big.Int {
// 	return new(big.Int).Mul(big.NewInt(gwei), big.NewInt(1000000000))
// }

// genesisInit is tools to init system contracts in genesis
type genesisInit struct {
	state   *state.StateDB
	header  *types.Header
	genesis *Genesis
}

// callContract executes contract in EVM
func (env *genesisInit) callContract(contract common.Address, method string, args ...interface{}) ([]byte, error) {
	// Pack method and args for data seg
	data, err := system.ABIPack(contract, method, args...)
	if err != nil {
		return nil, err
	}
	// Create EVM calling message
	msg := &Message{
		From:          EngineCaller,
		To:            &contract,
		Nonce:         0,
		Value:         big.NewInt(0),
		GasLimit:      math.MaxUint64,
		GasPrice:      big.NewInt(0),
		GasFeeCap:     big.NewInt(0),
		GasTipCap:     big.NewInt(0),
		Data:          data,
		AccessList:    nil,
		BlobHashes:    nil,
		BlobGasFeeCap: nil,
	}
	// Create EVM
	evm := vm.NewEVM(NewEVMBlockContext(env.header, nil, &env.header.Coinbase), NewEVMTxContext(msg), env.state, env.genesis.Config, vm.Config{})
	// Run evm call
	ret, _, err := evm.Call(vm.AccountRef(msg.From), *msg.To, msg.Data, msg.GasLimit, msg.Value)

	if err == vm.ErrExecutionReverted {
		reason, errUnpack := abi.UnpackRevert(common.CopyBytes(ret))
		if errUnpack != nil {
			reason = "internal error"
		}
		err = fmt.Errorf("%s: %s", err.Error(), reason)
	}

	if err != nil {
		log.Error("ExecuteMsg failed", "err", err, "ret", string(ret))
	}
	env.state.Finalise(true)
	return ret, err
}

// initStaking initializes Staking Contract
func (env *genesisInit) initStaking() error {
	contract, ok := env.genesis.Alloc[system.StakingContract]
	if !ok {
		return errors.New("Staking Contract is missing in genesis!")
	}

	if len(env.genesis.Validators) <= 0 {
		return errors.New("validators are missing in genesis!")
	}

	_, err := env.callContract(system.StakingContract, "initialize",
		contract.Init.Admin,
		contract.Init.BrcAddress,
		contract.Init.Epoch,
		contract.Init.FoundationPool)
	return err
}

// initValidators add validators into Staking contracts
// and set validator addresses to header extra data
// and return new header extra data
func (env *genesisInit) initValidators() ([]byte, error) {
	if len(env.genesis.Validators) <= 0 {
		return env.header.Extra, errors.New("validators are missing in genesis!")
	}
	activeSet := make([]common.Address, 0, len(env.genesis.Validators))
	extra := make([]byte, 0, extraVanity+common.AddressLength*len(env.genesis.Validators)+extraSeal)
	extra = append(extra, env.header.Extra[:extraVanity]...)
	for _, v := range env.genesis.Validators {
		if _, err := env.callContract(system.StakingContract, "initValidator",
			v.Address, v.Manager, v.Rate, v.AcceptDelegation); err != nil {
			return env.header.Extra, err
		}
		extra = append(extra, v.Address[:]...)
		activeSet = append(activeSet, v.Address)
	}
	extra = append(extra, env.header.Extra[len(env.header.Extra)-extraSeal:]...)
	env.header.Extra = extra
	if _, err := env.callContract(system.StakingContract, "updateActiveValidatorSet", activeSet); err != nil {
		return extra, err
	}
	return env.header.Extra, nil
}
