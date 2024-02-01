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

package system

import (
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/log"
)

const (
	// StakingABI contains methods to interactive with Staking contract.
	StakingABI = ` [
		{
		  "inputs": [
			{
			  "internalType": "address",
			  "name": "target",
			  "type": "address"
			}
		  ],
		  "name": "AddressEmptyCode",
		  "type": "error"
		},
		{
		  "inputs": [],
		  "name": "FailedInnerCall",
		  "type": "error"
		},
		{
		  "inputs": [
			{
			  "internalType": "address",
			  "name": "token",
			  "type": "address"
			}
		  ],
		  "name": "SafeERC20FailedOperation",
		  "type": "error"
		},
		{
		  "anonymous": false,
		  "inputs": [
			{
			  "indexed": true,
			  "internalType": "address",
			  "name": "oldAdmin",
			  "type": "address"
			},
			{
			  "indexed": true,
			  "internalType": "address",
			  "name": "newAdmin",
			  "type": "address"
			}
		  ],
		  "name": "AdminChanged",
		  "type": "event"
		},
		{
		  "anonymous": false,
		  "inputs": [
			{
			  "indexed": true,
			  "internalType": "address",
			  "name": "newAdmin",
			  "type": "address"
			}
		  ],
		  "name": "AdminChanging",
		  "type": "event"
		},
		{
		  "anonymous": false,
		  "inputs": [
			{
			  "indexed": true,
			  "internalType": "address",
			  "name": "val",
			  "type": "address"
			}
		  ],
		  "name": "ClaimWithoutUnboundStake",
		  "type": "event"
		},
		{
		  "anonymous": false,
		  "inputs": [],
		  "name": "LogDecreaseMissedBlocksCounter",
		  "type": "event"
		},
		{
		  "anonymous": false,
		  "inputs": [
			{
			  "indexed": true,
			  "internalType": "address",
			  "name": "val",
			  "type": "address"
			},
			{
			  "indexed": false,
			  "internalType": "uint256",
			  "name": "time",
			  "type": "uint256"
			}
		  ],
		  "name": "LogLazyPunishValidator",
		  "type": "event"
		},
		{
		  "anonymous": false,
		  "inputs": [
			{
			  "indexed": true,
			  "internalType": "bool",
			  "name": "opened",
			  "type": "bool"
			}
		  ],
		  "name": "PermissionLess",
		  "type": "event"
		},
		{
		  "anonymous": false,
		  "inputs": [
			{
			  "indexed": true,
			  "internalType": "address",
			  "name": "val",
			  "type": "address"
			},
			{
			  "indexed": true,
			  "internalType": "address",
			  "name": "recipient",
			  "type": "address"
			},
			{
			  "indexed": false,
			  "internalType": "uint256",
			  "name": "amount",
			  "type": "uint256"
			}
		  ],
		  "name": "StakeWithdrawn",
		  "type": "event"
		},
		{
		  "anonymous": false,
		  "inputs": [
			{
			  "indexed": true,
			  "internalType": "address",
			  "name": "changer",
			  "type": "address"
			},
			{
			  "indexed": false,
			  "internalType": "uint256",
			  "name": "oldStake",
			  "type": "uint256"
			},
			{
			  "indexed": false,
			  "internalType": "uint256",
			  "name": "newStake",
			  "type": "uint256"
			}
		  ],
		  "name": "TotalStakesChanged",
		  "type": "event"
		},
		{
		  "anonymous": false,
		  "inputs": [
			{
			  "indexed": true,
			  "internalType": "address",
			  "name": "val",
			  "type": "address"
			},
			{
			  "indexed": true,
			  "internalType": "address",
			  "name": "manager",
			  "type": "address"
			},
			{
			  "indexed": false,
			  "internalType": "uint256",
			  "name": "commissionRate",
			  "type": "uint256"
			},
			{
			  "indexed": false,
			  "internalType": "uint256",
			  "name": "stake",
			  "type": "uint256"
			},
			{
			  "indexed": false,
			  "internalType": "enum State",
			  "name": "st",
			  "type": "uint8"
			}
		  ],
		  "name": "ValidatorRegistered",
		  "type": "event"
		},
		{
		  "inputs": [],
		  "name": "ActiveValidatorFeePercent",
		  "outputs": [
			{
			  "internalType": "uint256",
			  "name": "",
			  "type": "uint256"
			}
		  ],
		  "stateMutability": "view",
		  "type": "function"
		},
		{
		  "inputs": [],
		  "name": "BackupValidatorFeePercent",
		  "outputs": [
			{
			  "internalType": "uint256",
			  "name": "",
			  "type": "uint256"
			}
		  ],
		  "stateMutability": "view",
		  "type": "function"
		},
		{
		  "inputs": [],
		  "name": "DecreaseRate",
		  "outputs": [
			{
			  "internalType": "uint256",
			  "name": "",
			  "type": "uint256"
			}
		  ],
		  "stateMutability": "view",
		  "type": "function"
		},
		{
		  "inputs": [],
		  "name": "JailPeriod",
		  "outputs": [
			{
			  "internalType": "uint256",
			  "name": "",
			  "type": "uint256"
			}
		  ],
		  "stateMutability": "view",
		  "type": "function"
		},
		{
		  "inputs": [],
		  "name": "LazyPunishFactor",
		  "outputs": [
			{
			  "internalType": "uint256",
			  "name": "",
			  "type": "uint256"
			}
		  ],
		  "stateMutability": "view",
		  "type": "function"
		},
		{
		  "inputs": [],
		  "name": "LazyPunishThreshold",
		  "outputs": [
			{
			  "internalType": "uint256",
			  "name": "",
			  "type": "uint256"
			}
		  ],
		  "stateMutability": "view",
		  "type": "function"
		},
		{
		  "inputs": [],
		  "name": "MaxBackups",
		  "outputs": [
			{
			  "internalType": "uint8",
			  "name": "",
			  "type": "uint8"
			}
		  ],
		  "stateMutability": "view",
		  "type": "function"
		},
		{
		  "inputs": [],
		  "name": "MaxStakes",
		  "outputs": [
			{
			  "internalType": "uint256",
			  "name": "",
			  "type": "uint256"
			}
		  ],
		  "stateMutability": "view",
		  "type": "function"
		},
		{
		  "inputs": [],
		  "name": "MaxValidators",
		  "outputs": [
			{
			  "internalType": "uint8",
			  "name": "",
			  "type": "uint8"
			}
		  ],
		  "stateMutability": "view",
		  "type": "function"
		},
		{
		  "inputs": [],
		  "name": "MinSelfStakes",
		  "outputs": [
			{
			  "internalType": "uint256",
			  "name": "",
			  "type": "uint256"
			}
		  ],
		  "stateMutability": "view",
		  "type": "function"
		},
		{
		  "inputs": [],
		  "name": "PunishBase",
		  "outputs": [
			{
			  "internalType": "uint256",
			  "name": "",
			  "type": "uint256"
			}
		  ],
		  "stateMutability": "view",
		  "type": "function"
		},
		{
		  "inputs": [],
		  "name": "StakeUnit",
		  "outputs": [
			{
			  "internalType": "uint256",
			  "name": "",
			  "type": "uint256"
			}
		  ],
		  "stateMutability": "view",
		  "type": "function"
		},
		{
		  "inputs": [],
		  "name": "ThresholdStakes",
		  "outputs": [
			{
			  "internalType": "uint256",
			  "name": "",
			  "type": "uint256"
			}
		  ],
		  "stateMutability": "view",
		  "type": "function"
		},
		{
		  "inputs": [],
		  "name": "UnboundLockPeriod",
		  "outputs": [
			{
			  "internalType": "uint256",
			  "name": "",
			  "type": "uint256"
			}
		  ],
		  "stateMutability": "view",
		  "type": "function"
		},
		{
		  "inputs": [],
		  "name": "acceptAdmin",
		  "outputs": [],
		  "stateMutability": "nonpayable",
		  "type": "function"
		},
		{
		  "inputs": [
			{
			  "internalType": "address",
			  "name": "_val",
			  "type": "address"
			},
			{
			  "internalType": "uint256",
			  "name": "_amount",
			  "type": "uint256"
			}
		  ],
		  "name": "addDelegation",
		  "outputs": [],
		  "stateMutability": "nonpayable",
		  "type": "function"
		},
		{
		  "inputs": [
			{
			  "internalType": "address",
			  "name": "_val",
			  "type": "address"
			},
			{
			  "internalType": "uint256",
			  "name": "_amount",
			  "type": "uint256"
			}
		  ],
		  "name": "addStake",
		  "outputs": [],
		  "stateMutability": "nonpayable",
		  "type": "function"
		},
		{
		  "inputs": [],
		  "name": "admin",
		  "outputs": [
			{
			  "internalType": "address",
			  "name": "",
			  "type": "address"
			}
		  ],
		  "stateMutability": "view",
		  "type": "function"
		},
		{
		  "inputs": [
			{
			  "internalType": "uint256",
			  "name": "",
			  "type": "uint256"
			}
		  ],
		  "name": "allValidatorAddrs",
		  "outputs": [
			{
			  "internalType": "address",
			  "name": "",
			  "type": "address"
			}
		  ],
		  "stateMutability": "view",
		  "type": "function"
		},
		{
		  "inputs": [
			{
			  "internalType": "address",
			  "name": "_val",
			  "type": "address"
			},
			{
			  "internalType": "address",
			  "name": "_stakeOwner",
			  "type": "address"
			}
		  ],
		  "name": "anyClaimable",
		  "outputs": [
			{
			  "internalType": "uint256",
			  "name": "claimableUnbound",
			  "type": "uint256"
			},
			{
			  "internalType": "uint256",
			  "name": "claimableRewards",
			  "type": "uint256"
			}
		  ],
		  "stateMutability": "view",
		  "type": "function"
		},
		{
		  "inputs": [],
		  "name": "blockEpoch",
		  "outputs": [
			{
			  "internalType": "uint256",
			  "name": "",
			  "type": "uint256"
			}
		  ],
		  "stateMutability": "view",
		  "type": "function"
		},
		{
		  "inputs": [],
		  "name": "brcToken",
		  "outputs": [
			{
			  "internalType": "contract IERC20",
			  "name": "",
			  "type": "address"
			}
		  ],
		  "stateMutability": "view",
		  "type": "function"
		},
		{
		  "inputs": [
			{
			  "internalType": "address",
			  "name": "newAdmin",
			  "type": "address"
			}
		  ],
		  "name": "changeAdmin",
		  "outputs": [],
		  "stateMutability": "nonpayable",
		  "type": "function"
		},
		{
		  "inputs": [],
		  "name": "decreaseMissedBlocksCounter",
		  "outputs": [],
		  "stateMutability": "nonpayable",
		  "type": "function"
		},
		{
		  "inputs": [
			{
			  "internalType": "address",
			  "name": "_val",
			  "type": "address"
			}
		  ],
		  "name": "delegatorClaimAny",
		  "outputs": [],
		  "stateMutability": "nonpayable",
		  "type": "function"
		},
		{
		  "inputs": [],
		  "name": "distributeBlockFee",
		  "outputs": [],
		  "stateMutability": "payable",
		  "type": "function"
		},
		{
		  "inputs": [
			{
			  "internalType": "address",
			  "name": "_val",
			  "type": "address"
			}
		  ],
		  "name": "exitDelegation",
		  "outputs": [],
		  "stateMutability": "nonpayable",
		  "type": "function"
		},
		{
		  "inputs": [
			{
			  "internalType": "address",
			  "name": "_val",
			  "type": "address"
			}
		  ],
		  "name": "exitStaking",
		  "outputs": [],
		  "stateMutability": "nonpayable",
		  "type": "function"
		},
		{
		  "inputs": [],
		  "name": "foundationPool",
		  "outputs": [
			{
			  "internalType": "address payable",
			  "name": "",
			  "type": "address"
			}
		  ],
		  "stateMutability": "view",
		  "type": "function"
		},
		{
		  "inputs": [],
		  "name": "getActiveValidators",
		  "outputs": [
			{
			  "internalType": "address[]",
			  "name": "",
			  "type": "address[]"
			}
		  ],
		  "stateMutability": "view",
		  "type": "function"
		},
		{
		  "inputs": [],
		  "name": "getAllValidatorsLength",
		  "outputs": [
			{
			  "internalType": "uint256",
			  "name": "",
			  "type": "uint256"
			}
		  ],
		  "stateMutability": "view",
		  "type": "function"
		},
		{
		  "inputs": [],
		  "name": "getBackupValidators",
		  "outputs": [
			{
			  "internalType": "address[]",
			  "name": "",
			  "type": "address[]"
			}
		  ],
		  "stateMutability": "view",
		  "type": "function"
		},
		{
		  "inputs": [
			{
			  "internalType": "address",
			  "name": "_val",
			  "type": "address"
			}
		  ],
		  "name": "getPunishRecord",
		  "outputs": [
			{
			  "internalType": "uint256",
			  "name": "",
			  "type": "uint256"
			}
		  ],
		  "stateMutability": "view",
		  "type": "function"
		},
		{
		  "inputs": [],
		  "name": "getPunishValidatorsLen",
		  "outputs": [
			{
			  "internalType": "uint256",
			  "name": "",
			  "type": "uint256"
			}
		  ],
		  "stateMutability": "view",
		  "type": "function"
		},
		{
		  "inputs": [
			{
			  "internalType": "uint8",
			  "name": "_count",
			  "type": "uint8"
			}
		  ],
		  "name": "getTopValidators",
		  "outputs": [
			{
			  "internalType": "address[]",
			  "name": "",
			  "type": "address[]"
			}
		  ],
		  "stateMutability": "view",
		  "type": "function"
		},
		{
		  "inputs": [
			{
			  "internalType": "address",
			  "name": "_val",
			  "type": "address"
			},
			{
			  "internalType": "address",
			  "name": "_manager",
			  "type": "address"
			},
			{
			  "internalType": "uint256",
			  "name": "_rate",
			  "type": "uint256"
			},
			{
			  "internalType": "bool",
			  "name": "_acceptDelegation",
			  "type": "bool"
			}
		  ],
		  "name": "initValidator",
		  "outputs": [],
		  "stateMutability": "nonpayable",
		  "type": "function"
		},
		{
		  "inputs": [
			{
			  "internalType": "address",
			  "name": "_admin",
			  "type": "address"
			},
			{
			  "internalType": "address",
			  "name": "_brcAddress",
			  "type": "address"
			},
			{
			  "internalType": "uint256",
			  "name": "_epoch",
			  "type": "uint256"
			},
			{
			  "internalType": "address payable",
			  "name": "_foundationPool",
			  "type": "address"
			}
		  ],
		  "name": "initialize",
		  "outputs": [],
		  "stateMutability": "nonpayable",
		  "type": "function"
		},
		{
		  "inputs": [],
		  "name": "initialized",
		  "outputs": [
			{
			  "internalType": "bool",
			  "name": "",
			  "type": "bool"
			}
		  ],
		  "stateMutability": "view",
		  "type": "function"
		},
		{
		  "inputs": [],
		  "name": "isOpened",
		  "outputs": [
			{
			  "internalType": "bool",
			  "name": "",
			  "type": "bool"
			}
		  ],
		  "stateMutability": "view",
		  "type": "function"
		},
		{
		  "inputs": [
			{
			  "internalType": "address",
			  "name": "_val",
			  "type": "address"
			}
		  ],
		  "name": "lazyPunish",
		  "outputs": [],
		  "stateMutability": "nonpayable",
		  "type": "function"
		},
		{
		  "inputs": [
			{
			  "internalType": "uint256",
			  "name": "",
			  "type": "uint256"
			}
		  ],
		  "name": "lazyPunishedValidators",
		  "outputs": [
			{
			  "internalType": "address",
			  "name": "",
			  "type": "address"
			}
		  ],
		  "stateMutability": "view",
		  "type": "function"
		},
		{
		  "inputs": [],
		  "name": "pendingAdmin",
		  "outputs": [
			{
			  "internalType": "address",
			  "name": "",
			  "type": "address"
			}
		  ],
		  "stateMutability": "view",
		  "type": "function"
		},
		{
		  "inputs": [
			{
			  "internalType": "address",
			  "name": "_oldVal",
			  "type": "address"
			},
			{
			  "internalType": "address",
			  "name": "_newVal",
			  "type": "address"
			},
			{
			  "internalType": "uint256",
			  "name": "_amount",
			  "type": "uint256"
			}
		  ],
		  "name": "reDelegation",
		  "outputs": [],
		  "stateMutability": "nonpayable",
		  "type": "function"
		},
		{
		  "inputs": [
			{
			  "internalType": "address",
			  "name": "_oldVal",
			  "type": "address"
			},
			{
			  "internalType": "address",
			  "name": "_newVal",
			  "type": "address"
			},
			{
			  "internalType": "uint256",
			  "name": "_amount",
			  "type": "uint256"
			}
		  ],
		  "name": "reStaking",
		  "outputs": [],
		  "stateMutability": "nonpayable",
		  "type": "function"
		},
		{
		  "inputs": [
			{
			  "internalType": "address",
			  "name": "_val",
			  "type": "address"
			},
			{
			  "internalType": "address",
			  "name": "_manager",
			  "type": "address"
			},
			{
			  "internalType": "uint256",
			  "name": "_rate",
			  "type": "uint256"
			},
			{
			  "internalType": "uint256",
			  "name": "_stakeAmount",
			  "type": "uint256"
			},
			{
			  "internalType": "bool",
			  "name": "_acceptDelegation",
			  "type": "bool"
			}
		  ],
		  "name": "registerValidator",
		  "outputs": [],
		  "stateMutability": "nonpayable",
		  "type": "function"
		},
		{
		  "inputs": [],
		  "name": "removePermission",
		  "outputs": [],
		  "stateMutability": "nonpayable",
		  "type": "function"
		},
		{
		  "inputs": [
			{
			  "internalType": "address",
			  "name": "_val",
			  "type": "address"
			},
			{
			  "internalType": "uint256",
			  "name": "_amount",
			  "type": "uint256"
			}
		  ],
		  "name": "subDelegation",
		  "outputs": [],
		  "stateMutability": "nonpayable",
		  "type": "function"
		},
		{
		  "inputs": [
			{
			  "internalType": "address",
			  "name": "_val",
			  "type": "address"
			},
			{
			  "internalType": "uint256",
			  "name": "_amount",
			  "type": "uint256"
			}
		  ],
		  "name": "subStake",
		  "outputs": [],
		  "stateMutability": "nonpayable",
		  "type": "function"
		},
		{
		  "inputs": [],
		  "name": "totalStakes",
		  "outputs": [
			{
			  "internalType": "uint256",
			  "name": "",
			  "type": "uint256"
			}
		  ],
		  "stateMutability": "view",
		  "type": "function"
		},
		{
		  "inputs": [
			{
			  "internalType": "address[]",
			  "name": "_newSet",
			  "type": "address[]"
			}
		  ],
		  "name": "updateActiveValidatorSet",
		  "outputs": [],
		  "stateMutability": "nonpayable",
		  "type": "function"
		},
		{
		  "inputs": [
			{
			  "internalType": "address",
			  "name": "",
			  "type": "address"
			}
		  ],
		  "name": "valInfos",
		  "outputs": [
			{
			  "internalType": "uint256",
			  "name": "stake",
			  "type": "uint256"
			},
			{
			  "internalType": "uint256",
			  "name": "unWithdrawn",
			  "type": "uint256"
			}
		  ],
		  "stateMutability": "view",
		  "type": "function"
		},
		{
		  "inputs": [
			{
			  "internalType": "address",
			  "name": "",
			  "type": "address"
			}
		  ],
		  "name": "valMaps",
		  "outputs": [
			{
			  "internalType": "contract IValidator",
			  "name": "",
			  "type": "address"
			}
		  ],
		  "stateMutability": "view",
		  "type": "function"
		},
		{
		  "inputs": [
			{
			  "internalType": "address",
			  "name": "_val",
			  "type": "address"
			}
		  ],
		  "name": "validatorClaimAny",
		  "outputs": [],
		  "stateMutability": "nonpayable",
		  "type": "function"
		}
	  ]`
)

var (
	StakingContract = common.HexToAddress("0x000000000000000000000000000000000000F000")

	abiMap map[common.Address]abi.ABI
)

// init the abiMap
func init() {
	abiMap = make(map[common.Address]abi.ABI, 0)

	for addr, rawAbi := range map[common.Address]string{
		StakingContract: StakingABI,
	} {
		if abi, err := abi.JSON(strings.NewReader(rawAbi)); err != nil {
			panic(err)
		} else {
			abiMap[addr] = abi
		}
	}
}

// ABI return abi for given contract calling
func ABI(contract common.Address) abi.ABI {
	contractABI, ok := abiMap[contract]
	if !ok {
		log.Crit("Unknown system contract: " + contract.String())
	}
	return contractABI
}

// ABIPack generates the data field for given contract calling
func ABIPack(contract common.Address, method string, args ...interface{}) ([]byte, error) {
	return ABI(contract).Pack(method, args...)
}
