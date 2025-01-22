package txpool

import (
	"errors"
	"fmt"
	"math"
	"math/big"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/contracts/discountsetting"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
)

type CallContext struct {
	Statedb      *state.StateDB
	Header       *types.Header
	ChainContext core.ChainContext
	ChainConfig  *params.ChainConfig
}

type Discounts struct {
	discounts map[common.Address]*big.Int
}

func NewDiscounts(addrlist []common.Address, tiplist []*big.Int) *Discounts {
	log.Debug("NewDiscounts ", addrlist, tiplist)
	discounts := make(map[common.Address]*big.Int)
	for i, addr := range addrlist {
		discounts[addr] = tiplist[i]
	}

	return &Discounts{discounts}
}

func (discounts *Discounts) GetTip(addr *common.Address, mintip *big.Int) *big.Int {
	if addr == nil {
		return mintip
	} else {
		tip, ok := discounts.discounts[*addr]
		if ok {
			return tip
		} else {
			return mintip
		}
	}
}

func GetDiscounts(ctx *CallContext, contract common.Address) (*Discounts, error) {
	if contract == (common.Address{}) {
		return NewDiscounts(nil, nil), nil
	}

	const method = "GetDiscounts"
	result1, result2, err := contractRead(ctx, contract, method)
	if err != nil {
		log.Error("GetDiscounts contractRead failed", "err", err)
		return nil, err
	}
	addrlist, ok := result1.([]common.Address)
	if !ok {
		return nil, errors.New("GetDiscounts: invalid addrlist format")
	}
	tiplist, ok := result2.([]*big.Int)
	if !ok {
		return nil, errors.New("GetDiscounts: invalid tiplist format")
	}
	return NewDiscounts(addrlist, tiplist), nil
}

// contractRead perform contract read
func contractRead(ctx *CallContext, contract common.Address, method string, args ...interface{}) (interface{}, interface{}, error) {
	ret, err := contractReadAll(ctx, contract, method, args...)
	if err != nil {
		return nil, nil, err
	}
	if len(ret) != 2 {
		return nil, nil, errors.New(method + ": invalid result length")
	}
	return ret[0], ret[1], nil
}

// contractReadAll perform contract Read and return all results
func contractReadAll(ctx *CallContext, contract common.Address, method string, args ...interface{}) ([]interface{}, error) {
	abi := discountsetting.ABI()
	result, err := contractReadBytes(ctx, contract, &abi, method, args...)
	if err != nil {
		return nil, err
	}
	// unpack data
	ret, err := abi.Unpack(method, result)
	if err != nil {
		return nil, err
	}
	return ret, nil
}

// contractReadBytes perform read contract and returns bytes
func contractReadBytes(ctx *CallContext, contract common.Address, abi *abi.ABI, method string, args ...interface{}) ([]byte, error) {
	data, err := abi.Pack(method, args...)
	if err != nil {
		log.Error("Can't pack data", "method", method, "error", err)
		return nil, err
	}
	result, err := CallContract(ctx, &contract, data)
	if err != nil {
		log.Error("Failed to execute", "method", method, "err", err)
		return nil, err
	}
	return result, nil
}

// CallContract executes transaction sent to system contracts.
func CallContract(ctx *CallContext, to *common.Address, data []byte) (ret []byte, err error) {
	return CallContractWithValue(ctx /*ctx.Header.Coinbase*/, *to, to, data, big.NewInt(0))
}

// CallContract executes transaction sent to system contracts.
func CallContractWithValue(ctx *CallContext, from common.Address, to *common.Address, data []byte, value *big.Int) (ret []byte, err error) {
	evm := vm.NewEVM(core.NewEVMBlockContext(ctx.Header, ctx.ChainContext, nil), vm.TxContext{
		Origin:   from,
		GasPrice: big.NewInt(0),
	}, ctx.Statedb, ctx.ChainConfig, vm.Config{})

	ret, _, err = evm.Call(vm.AccountRef(from), *to, data, math.MaxUint64, value)

	return ret, WrapVMError(err, ret)
}

// WrapVMError wraps vm error with readable reason
func WrapVMError(err error, ret []byte) error {
	if err == vm.ErrExecutionReverted {
		reason, errUnpack := abi.UnpackRevert(common.CopyBytes(ret))
		if errUnpack != nil {
			reason = "internal error"
		}
		return fmt.Errorf("%s: %s", err.Error(), reason)
	}
	return err
}
