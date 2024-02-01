package systemcontract

import (
	"bytes"
	"errors"
	"math/big"
	"sort"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/contracts/system"
	"github.com/ethereum/go-ethereum/log"
)

const TopValidatorNum uint8 = 21

// AddrAscend implements the sort interface to allow sorting a list of addresses
type AddrAscend []common.Address

func (s AddrAscend) Len() int           { return len(s) }
func (s AddrAscend) Less(i, j int) bool { return bytes.Compare(s[i][:], s[j][:]) < 0 }
func (s AddrAscend) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }

type Proposal struct {
	Id     *big.Int
	Action *big.Int
	From   common.Address
	To     common.Address
	Value  *big.Int
	Data   []byte
}

// GetTopValidators return the result of calling method `getTopValidators` in Staking contract
func GetTopValidators(ctx *CallContext) ([]common.Address, error) {
	const method = "getTopValidators"
	result, err := contractRead(ctx, system.StakingContract, method, TopValidatorNum)
	if err != nil {
		log.Error("GetTopValidators contractRead failed", "err", err)
		return []common.Address{}, err
	}
	validators, ok := result.([]common.Address)
	if !ok {
		return []common.Address{}, errors.New("GetTopValidators: invalid validator format")
	}
	sort.Sort(AddrAscend(validators))
	return validators, nil
}

// UpdateActiveValidatorSet return the result of calling method `updateActiveValidatorSet` in Staking contract
func UpdateActiveValidatorSet(ctx *CallContext, newValidators []common.Address) error {
	const method = "updateActiveValidatorSet"
	err := contractWrite(ctx, system.StakingContract, method, newValidators)
	if err != nil {
		log.Error("UpdateActiveValidatorSet failed", "newValidators", newValidators, "err", err)
	}
	return err
}

// DecreaseMissedBlocksCounter return the result of calling method `decreaseMissedBlocksCounter` in Staking contract
func DecreaseMissedBlocksCounter(ctx *CallContext) error {
	const method = "decreaseMissedBlocksCounter"
	err := contractWrite(ctx, system.StakingContract, method)
	if err != nil {
		log.Error("DecreaseMissedBlocksCounter failed", "err", err)
	}
	return err
}

// DistributeBlockFee return the result of calling method `distributeBlockFee` in Staking contract
func DistributeBlockFee(ctx *CallContext, fee *big.Int) error {
	const method = "distributeBlockFee"
	data, err := system.ABIPack(system.StakingContract, method)
	if err != nil {
		log.Error("Can't pack data for distributeBlockFee", "error", err)
		return err
	}
	if _, err := CallContractWithValue(ctx, EngineCaller, &system.StakingContract, data, fee); err != nil {
		log.Error("DistributeBlockFee failed", "fee", fee, "err", err)
		return err
	}
	return nil
}

// LazyPunish return the result of calling method `lazyPunish` in Staking contract
func LazyPunish(ctx *CallContext, validator common.Address) error {
	const method = "lazyPunish"
	err := contractWrite(ctx, system.StakingContract, method, validator)
	if err != nil {
		log.Error("LazyPunish failed", "validator", validator, "err", err)
	}
	return err
}

// contractRead perform contract read
func contractRead(ctx *CallContext, contract common.Address, method string, args ...interface{}) (interface{}, error) {
	ret, err := contractReadAll(ctx, contract, method, args...)
	if err != nil {
		return nil, err
	}
	if len(ret) != 1 {
		return nil, errors.New(method + ": invalid result length")
	}
	return ret[0], nil
}

// contractReadAll perform contract Read and return all results
func contractReadAll(ctx *CallContext, contract common.Address, method string, args ...interface{}) ([]interface{}, error) {
	abi := system.ABI(contract)
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

// contractWrite perform write contract
func contractWrite(ctx *CallContext, contract common.Address, method string, args ...interface{}) error {
	data, err := system.ABIPack(contract, method, args...)
	if err != nil {
		log.Error("Can't pack data", "method", method, "error", err)
		return err
	}
	if _, err := CallContract(ctx, &contract, data); err != nil {
		log.Error("Failed to execute", "method", method, "err", err)
		return err
	}
	return nil
}
