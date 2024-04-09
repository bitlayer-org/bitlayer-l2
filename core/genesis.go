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

package core

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/contracts/system"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/ethereum/go-ethereum/triedb"
	"github.com/ethereum/go-ethereum/triedb/pathdb"
	"github.com/holiman/uint256"
)

//go:generate go run github.com/fjl/gencodec -type Genesis -field-override genesisSpecMarshaling -out gen_genesis.go

var errGenesisNoConfig = errors.New("genesis has no chain configuration")

// Deprecated: use types.GenesisAccount instead.
type GenesisAccount = types.Account

// Deprecated: use types.GenesisAlloc instead.
type GenesisAlloc = types.GenesisAlloc

// Genesis specifies the header fields, state of a genesis block. It also defines hard
// fork switch-over blocks through the chain configuration.
type Genesis struct {
	Config     *params.ChainConfig `json:"config"`
	Nonce      uint64              `json:"nonce"`
	Timestamp  uint64              `json:"timestamp"`
	ExtraData  []byte              `json:"extraData"`
	GasLimit   uint64              `json:"gasLimit"   gencodec:"required"`
	Difficulty *big.Int            `json:"difficulty" gencodec:"required"`
	Mixhash    common.Hash         `json:"mixHash"`
	Coinbase   common.Address      `json:"coinbase"`
	Alloc      types.GenesisAlloc  `json:"alloc"      gencodec:"required"`
	Validators []ValidatorInfo     `json:"validators"`

	// These fields are used for consensus tests. Please don't use them
	// in actual genesis blocks.
	Number        uint64      `json:"number"`
	GasUsed       uint64      `json:"gasUsed"`
	ParentHash    common.Hash `json:"parentHash"`
	BaseFee       *big.Int    `json:"baseFeePerGas"` // EIP-1559
	ExcessBlobGas *uint64     `json:"excessBlobGas"` // EIP-4844
	BlobGasUsed   *uint64     `json:"blobGasUsed"`   // EIP-4844
}

// ValidatorInfo represents the info of initial validators
type ValidatorInfo struct {
	Address          common.Address `json:"address"         gencodec:"required"`
	Manager          common.Address `json:"manager"         gencodec:"required"`
	Rate             *big.Int       `json:"rate,omitempty"`
	AcceptDelegation bool           `json:"acceptDelegation,omitempty"`
}

type validatorInfoMarshaling struct {
	Rate *math.HexOrDecimal256
}

// makeValidator creates ValidatorInfo
func makeValidator(address, manager, rate string, acceptDelegation bool) ValidatorInfo {
	rateNum, ok := new(big.Int).SetString(rate, 10)
	if !ok {
		panic("Failed to make validator info due to invalid rate")
	}
	return ValidatorInfo{
		Address:          common.HexToAddress(address),
		Manager:          common.HexToAddress(manager),
		Rate:             rateNum,
		AcceptDelegation: acceptDelegation,
	}
}

func ReadGenesis(db ethdb.Database) (*Genesis, error) {
	var genesis Genesis
	stored := rawdb.ReadCanonicalHash(db, 0)
	if (stored == common.Hash{}) {
		return nil, fmt.Errorf("invalid genesis hash in database: %x", stored)
	}
	blob := rawdb.ReadGenesisStateSpec(db, stored)
	if blob == nil {
		return nil, errors.New("genesis state missing from db")
	}
	if len(blob) != 0 {
		if err := genesis.Alloc.UnmarshalJSON(blob); err != nil {
			return nil, fmt.Errorf("could not unmarshal genesis state json: %s", err)
		}
	}
	genesis.Config = rawdb.ReadChainConfig(db, stored)
	if genesis.Config == nil {
		return nil, errors.New("genesis config missing from db")
	}
	genesisBlock := rawdb.ReadBlock(db, stored, 0)
	if genesisBlock == nil {
		return nil, errors.New("genesis block missing from db")
	}
	genesisHeader := genesisBlock.Header()
	genesis.Nonce = genesisHeader.Nonce.Uint64()
	genesis.Timestamp = genesisHeader.Time
	genesis.ExtraData = genesisHeader.Extra
	genesis.GasLimit = genesisHeader.GasLimit
	genesis.Difficulty = genesisHeader.Difficulty
	genesis.Mixhash = genesisHeader.MixDigest
	genesis.Coinbase = genesisHeader.Coinbase
	genesis.BaseFee = genesisHeader.BaseFee
	genesis.ExcessBlobGas = genesisHeader.ExcessBlobGas
	genesis.BlobGasUsed = genesisHeader.BlobGasUsed

	return &genesis, nil
}

// hashAlloc computes the state root according to the genesis specification.
func (g *Genesis) hashAlloc(ga *types.GenesisAlloc, isVerkle bool) (*types.Header, error) {
	// If a genesis-time verkle trie is requested, create a trie config
	// with the verkle trie enabled so that the tree can be initialized
	// as such.
	var config *triedb.Config
	if isVerkle {
		config = &triedb.Config{
			PathDB:   pathdb.Defaults,
			IsVerkle: true,
		}
	}
	// Create an ephemeral in-memory database for computing hash,
	// all the derived states will be discarded to not pollute disk.
	db := state.NewDatabaseWithConfig(rawdb.NewMemoryDatabase(), config)
	statedb, err := state.New(types.EmptyRootHash, db, nil)
	if err != nil {
		return nil, err
	}
	for addr, account := range *ga {
		if account.Balance != nil {
			statedb.AddBalance(addr, uint256.MustFromBig(account.Balance))
		}
		statedb.SetCode(addr, account.Code)
		statedb.SetNonce(addr, account.Nonce)
		for key, value := range account.Storage {
			statedb.SetState(addr, key, value)
		}
	}
	head := &types.Header{
		Number:     new(big.Int).SetUint64(g.Number),
		Nonce:      types.EncodeNonce(g.Nonce),
		Time:       g.Timestamp,
		ParentHash: g.ParentHash,
		Extra:      g.ExtraData,
		GasLimit:   g.GasLimit,
		GasUsed:    g.GasUsed,
		BaseFee:    g.BaseFee,
		Difficulty: g.Difficulty,
		MixDigest:  g.Mixhash,
		Coinbase:   g.Coinbase,
	}

	// Handle the Merlion related
	if g.Config != nil && g.Config.Merlion != nil {
		// if len(head.Extra) < 32 {
		// 	return nil, errors.New("head.extra length not match!")
		// }
		// init system contract
		gInit := &genesisInit{statedb, head, g}
		for name, initSystemContract := range map[string]func() error{
			"Staking": gInit.initStaking,
		} {
			if err = initSystemContract(); err != nil {
				log.Crit("Failed to init system contract in head", "contract", name, "err", err)
			}
		}
		// Set validoter info
		if head.Extra, err = gInit.initValidators(); err != nil {
			log.Crit("Failed to init Validators in head", "err", err)
		}
	}

	root, err := statedb.Commit(0, false)
	if err != nil {
		log.Crit("Failed to statedb.Commit", "err", err)
	}
	head.Root = root
	log.Info("to block hash root", root.String())
	return head, nil
}

func (g *Genesis) flushAlloc(ga *types.GenesisAlloc, db ethdb.Database, triedb *triedb.Database, head *types.Header) error {
	statedb, err := state.New(types.EmptyRootHash, state.NewDatabaseWithNodeDB(db, triedb), nil)
	if err != nil {
		return err
	}
	for addr, account := range *ga {
		if account.Balance != nil {
			statedb.AddBalance(addr, uint256.MustFromBig(account.Balance))
		}
		statedb.SetCode(addr, account.Code)
		statedb.SetNonce(addr, account.Nonce)
		for key, value := range account.Storage {
			statedb.SetState(addr, key, value)
		}
	}
	// Handle the Merlion related
	if g.Config != nil && g.Config.Merlion != nil {
		// init system contract
		gInit := &genesisInit{statedb, head, g}
		for name, initSystemContract := range map[string]func() error{
			"Staking": gInit.initStaking,
		} {
			if err = initSystemContract(); err != nil {
				log.Crit("Failed to init system contract in flush", "contract", name, "err", err)
			}
		}
		// Set validoter info
		if _, err = gInit.initValidators(); err != nil {
			log.Crit("Failed to init Validators in flush", "err", err)
		}
	}
	root, err := statedb.Commit(0, false)
	if err != nil {
		return err
	}
	// Commit newly generated states into disk if it's not empty.
	if root != types.EmptyRootHash {
		if err := triedb.Commit(root, true); err != nil {
			return err
		}
	}
	// Marshal the genesis state specification and persist.
	blob, err := json.Marshal(ga)
	if err != nil {
		return err
	}
	rawdb.WriteGenesisStateSpec(db, head.Hash(), blob)
	return nil
}

// field type overrides for gencodec
type genesisSpecMarshaling struct {
	Nonce         math.HexOrDecimal64
	Timestamp     math.HexOrDecimal64
	ExtraData     hexutil.Bytes
	GasLimit      math.HexOrDecimal64
	GasUsed       math.HexOrDecimal64
	Number        math.HexOrDecimal64
	Difficulty    *math.HexOrDecimal256
	Alloc         map[common.UnprefixedAddress]types.Account
	BaseFee       *math.HexOrDecimal256
	ExcessBlobGas *math.HexOrDecimal64
	BlobGasUsed   *math.HexOrDecimal64
}

// GenesisMismatchError is raised when trying to overwrite an existing
// genesis block with an incompatible one.
type GenesisMismatchError struct {
	Stored, New common.Hash
}

func (e *GenesisMismatchError) Error() string {
	return fmt.Sprintf("database contains incompatible genesis (have %x, new %x)", e.Stored, e.New)
}

// ChainOverrides contains the changes to chain config.
type ChainOverrides struct {
	OverrideCancun *uint64
	OverrideVerkle *uint64
}

// SetupGenesisBlock writes or updates the genesis block in db.
// The block that will be used is:
//
//	                     genesis == nil       genesis != nil
//	                  +------------------------------------------
//	db has no genesis |  main-net default  |  genesis
//	db has genesis    |  from DB           |  genesis (if compatible)
//
// The stored chain configuration will be updated if it is compatible (i.e. does not
// specify a fork block below the local head block). In case of a conflict, the
// error is a *params.ConfigCompatError and the new, unwritten config is returned.
//
// The returned chain configuration is never nil.
func SetupGenesisBlock(db ethdb.Database, triedb *triedb.Database, genesis *Genesis) (*params.ChainConfig, common.Hash, error) {
	return SetupGenesisBlockWithOverride(db, triedb, genesis, nil)
}

func SetupGenesisBlockWithOverride(db ethdb.Database, triedb *triedb.Database, genesis *Genesis, overrides *ChainOverrides) (*params.ChainConfig, common.Hash, error) {
	if genesis != nil && genesis.Config == nil {
		return params.AllEthashProtocolChanges, common.Hash{}, errGenesisNoConfig
	}
	applyOverrides := func(config *params.ChainConfig) {
		if config != nil {
			if overrides != nil && overrides.OverrideCancun != nil {
				config.CancunTime = overrides.OverrideCancun
			}
			if overrides != nil && overrides.OverrideVerkle != nil {
				config.VerkleTime = overrides.OverrideVerkle
			}
		}
	}
	// Just commit the new block if there is no stored genesis block.
	stored := rawdb.ReadCanonicalHash(db, 0)
	if (stored == common.Hash{}) {
		if genesis == nil {
			log.Info("Writing default main-net genesis block")
			genesis = DefaultBitlayerL2GenesisBlock()
		} else {
			log.Info("Writing custom genesis block")
		}
		applyOverrides(genesis.Config)
		block, err := genesis.Commit(db, triedb)
		if err != nil {
			return genesis.Config, common.Hash{}, err
		}
		return genesis.Config, block.Hash(), nil
	}
	// The genesis block is present(perhaps in ancient database) while the
	// state database is not initialized yet. It can happen that the node
	// is initialized with an external ancient store. Commit genesis state
	// in this case.
	header := rawdb.ReadHeader(db, stored, 0)
	if header.Root != types.EmptyRootHash && !triedb.Initialized(header.Root) {
		if genesis == nil {
			genesis = DefaultBitlayerL2GenesisBlock()
		}
		applyOverrides(genesis.Config)
		// Ensure the stored genesis matches with the given one.
		hash := genesis.ToBlock().Hash()
		if hash != stored {
			return genesis.Config, hash, &GenesisMismatchError{stored, hash}
		}
		block, err := genesis.Commit(db, triedb)
		if err != nil {
			return genesis.Config, hash, err
		}
		return genesis.Config, block.Hash(), nil
	}
	// Check whether the genesis block is already written.
	if genesis != nil {
		applyOverrides(genesis.Config)
		hash := genesis.ToBlock().Hash()
		if hash != stored {
			return genesis.Config, hash, &GenesisMismatchError{stored, hash}
		}
	}
	// Get the existing chain configuration.
	newcfg := genesis.configOrDefault(stored)
	applyOverrides(newcfg)
	if err := newcfg.CheckConfigForkOrder(); err != nil {
		return newcfg, common.Hash{}, err
	}
	storedcfg := rawdb.ReadChainConfig(db, stored)
	if storedcfg == nil {
		log.Warn("Found genesis block without chain config")
		rawdb.WriteChainConfig(db, stored, newcfg)
		return newcfg, stored, nil
	}
	storedData, _ := json.Marshal(storedcfg)
	// Special case: if a private network is being used (no genesis and also no
	// mainnet hash in the database), we must not apply the `configOrDefault`
	// chain config as that would be AllProtocolChanges (applying any new fork
	// on top of an existing private network genesis block). In that case, only
	// apply the overrides.
	if genesis == nil && stored != params.BitlayerL2MainnetGenesisHash {
		newcfg = storedcfg
		applyOverrides(newcfg)
	}
	// Check config compatibility and write the config. Compatibility errors
	// are returned to the caller unless we're already at block zero.
	head := rawdb.ReadHeadHeader(db)
	if head == nil {
		return newcfg, stored, errors.New("missing head header")
	}
	// Check whether consensus config of Merlion is changed
	if !storedcfg.IsMerlionCompatible(newcfg) {
		return nil, common.Hash{}, errors.New("MerlionConfig is not compatible with stored")
	}
	compatErr := storedcfg.CheckCompatible(newcfg, head.Number.Uint64(), head.Time)
	if compatErr != nil && ((head.Number.Uint64() != 0 && compatErr.RewindToBlock != 0) || (head.Time != 0 && compatErr.RewindToTime != 0)) {
		return newcfg, stored, compatErr
	}
	// Don't overwrite if the old is identical to the new
	if newData, _ := json.Marshal(newcfg); !bytes.Equal(storedData, newData) {
		rawdb.WriteChainConfig(db, stored, newcfg)
	}
	return newcfg, stored, nil
}

// LoadChainConfig loads the stored chain config if it is already present in
// database, otherwise, return the config in the provided genesis specification.
func LoadChainConfig(db ethdb.Database, genesis *Genesis) (*params.ChainConfig, error) {
	// Load the stored chain config from the database. It can be nil
	// in case the database is empty. Notably, we only care about the
	// chain config corresponds to the canonical chain.
	stored := rawdb.ReadCanonicalHash(db, 0)
	if stored != (common.Hash{}) {
		storedcfg := rawdb.ReadChainConfig(db, stored)
		if storedcfg != nil {
			return storedcfg, nil
		}
	}
	// Load the config from the provided genesis specification
	if genesis != nil {
		// Reject invalid genesis spec without valid chain config
		if genesis.Config == nil {
			return nil, errGenesisNoConfig
		}
		// If the canonical genesis header is present, but the chain
		// config is missing(initialize the empty leveldb with an
		// external ancient chain segment), ensure the provided genesis
		// is matched.
		if stored != (common.Hash{}) && genesis.ToBlock().Hash() != stored {
			return nil, &GenesisMismatchError{stored, genesis.ToBlock().Hash()}
		}
		return genesis.Config, nil
	}
	// There is no stored chain config and no new config provided,
	// In this case the default chain config(mainnet) will be used
	return params.BitlayerL2MainnetChainConfig, nil
}

func (g *Genesis) configOrDefault(ghash common.Hash) *params.ChainConfig {
	switch {
	case g != nil:
		return g.Config
	case ghash == params.MainnetGenesisHash:
		return params.MainnetChainConfig
	case ghash == params.HoleskyGenesisHash:
		return params.HoleskyChainConfig
	case ghash == params.SepoliaGenesisHash:
		return params.SepoliaChainConfig
	case ghash == params.GoerliGenesisHash:
		return params.GoerliChainConfig
	case ghash == params.BitlayerL2MainnetGenesisHash:
		return params.BitlayerL2MainnetChainConfig
	case ghash == params.BitlayerL2TestnetGenesisHash:
		return params.BitlayerL2TestnetChainConfig
	default:
		return params.AllMerlionProtocolChanges
	}
}

// IsVerkle indicates whether the state is already stored in a verkle
// tree at genesis time.
func (g *Genesis) IsVerkle() bool {
	return g.Config.IsVerkle(new(big.Int).SetUint64(g.Number), g.Timestamp)
}

// ToBlock returns the genesis block according to genesis specification.
func (g *Genesis) ToBlock() *types.Block {
	head, err := g.hashAlloc(&g.Alloc, g.IsVerkle())
	if err != nil {
		panic(err)
	}
	if g.GasLimit == 0 {
		head.GasLimit = params.GenesisGasLimit
	}
	if g.Difficulty == nil && g.Mixhash == (common.Hash{}) {
		head.Difficulty = params.GenesisDifficulty
	}
	if g.Config != nil && g.Config.IsLondon(common.Big0) {
		if g.BaseFee != nil {
			head.BaseFee = g.BaseFee
		} else {
			head.BaseFee = new(big.Int).SetUint64(params.InitialBaseFee)
		}
	}

	var withdrawals []*types.Withdrawal
	if conf := g.Config; conf != nil {
		num := big.NewInt(int64(g.Number))
		if conf.IsShanghai(num, g.Timestamp) {
			head.WithdrawalsHash = &types.EmptyWithdrawalsHash
			withdrawals = make([]*types.Withdrawal, 0)
		}
		if conf.IsCancun(num, g.Timestamp) {
			// EIP-4788: The parentBeaconBlockRoot of the genesis block is always
			// the zero hash. This is because the genesis block does not have a parent
			// by definition.
			head.ParentBeaconRoot = new(common.Hash)
			// EIP-4844 fields
			head.ExcessBlobGas = g.ExcessBlobGas
			head.BlobGasUsed = g.BlobGasUsed
			if head.ExcessBlobGas == nil {
				head.ExcessBlobGas = new(uint64)
			}
			if head.BlobGasUsed == nil {
				head.BlobGasUsed = new(uint64)
			}
		}
	}
	return types.NewBlock(head, nil, nil, nil, trie.NewStackTrie(nil)).WithWithdrawals(withdrawals)
}

// Commit writes the block and state of a genesis specification to the database.
// The block is committed as the canonical head block.
func (g *Genesis) Commit(db ethdb.Database, triedb *triedb.Database) (*types.Block, error) {
	if g.Config != nil && g.Config.Merlion != nil {
		if len(g.ExtraData) < 32 {
			return nil, errors.New("extra data length not match")
		}
	}
	block := g.ToBlock()
	if block.Number().Sign() != 0 {
		return nil, errors.New("can't commit genesis block with number > 0")
	}
	config := g.Config
	if config == nil {
		config = params.AllEthashProtocolChanges
	}
	if err := config.CheckConfigForkOrder(); err != nil {
		return nil, err
	}
	if config.Clique != nil && len(block.Extra()) < 32+crypto.SignatureLength {
		return nil, errors.New("can't start clique chain without signers")
	}
	// All the checks has passed, flushAlloc the states derived from the genesis
	// specification as well as the specification itself into the provided
	// database.
	if err := g.flushAlloc(&g.Alloc, db, triedb, block.Header()); err != nil {
		return nil, err
	}
	log.Info("genesis block hash", block.Hash().String())
	rawdb.WriteTd(db, block.Hash(), block.NumberU64(), block.Difficulty())
	rawdb.WriteBlock(db, block)
	rawdb.WriteReceipts(db, block.Hash(), block.NumberU64(), nil)
	rawdb.WriteCanonicalHash(db, block.Hash(), block.NumberU64())
	rawdb.WriteHeadBlockHash(db, block.Hash())
	rawdb.WriteHeadFastBlockHash(db, block.Hash())
	rawdb.WriteHeadHeaderHash(db, block.Hash())
	rawdb.WriteChainConfig(db, block.Hash(), config)
	return block, nil
}

// MustCommit writes the genesis block and state to db, panicking on error.
// The block is committed as the canonical head block.
func (g *Genesis) MustCommit(db ethdb.Database, triedb *triedb.Database) *types.Block {
	block, err := g.Commit(db, triedb)
	if err != nil {
		panic(err)
	}
	return block
}

// DefaultGenesisBlock returns the Ethereum main net genesis block.
func DefaultGenesisBlock() *Genesis {
	return &Genesis{
		Config:     params.MainnetChainConfig,
		Nonce:      66,
		ExtraData:  hexutil.MustDecode("0x11bbe8db4e347b4e8c937c1c8370e4b5ed33adb3db69cbdb7a38e1e50b1b82fa"),
		GasLimit:   5000,
		Difficulty: big.NewInt(17179869184),
		Alloc:      decodePrealloc(mainnetAllocData),
	}
}

// DefaultGoerliGenesisBlock returns the Görli network genesis block.
func DefaultGoerliGenesisBlock() *Genesis {
	return &Genesis{
		Config:     params.GoerliChainConfig,
		Timestamp:  1548854791,
		ExtraData:  hexutil.MustDecode("0x22466c6578692069732061207468696e6722202d204166726900000000000000e0a2bd4258d2768837baa26a28fe71dc079f84c70000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
		GasLimit:   10485760,
		Difficulty: big.NewInt(1),
		Alloc:      decodePrealloc(goerliAllocData),
	}
}

// DefaultSepoliaGenesisBlock returns the Sepolia network genesis block.
func DefaultSepoliaGenesisBlock() *Genesis {
	return &Genesis{
		Config:     params.SepoliaChainConfig,
		Nonce:      0,
		ExtraData:  []byte("Sepolia, Athens, Attica, Greece!"),
		GasLimit:   0x1c9c380,
		Difficulty: big.NewInt(0x20000),
		Timestamp:  1633267481,
		Alloc:      decodePrealloc(sepoliaAllocData),
	}
}

// DefaultHoleskyGenesisBlock returns the Holesky network genesis block.
func DefaultHoleskyGenesisBlock() *Genesis {
	return &Genesis{
		Config:     params.HoleskyChainConfig,
		Nonce:      0x1234,
		GasLimit:   0x17d7840,
		Difficulty: big.NewInt(0x01),
		Timestamp:  1695902100,
		Alloc:      decodePrealloc(holeskyAllocData),
	}
}

// DeveloperGenesisBlock returns the 'geth --dev' genesis block.
func DeveloperGenesisBlock(gasLimit uint64, faucet *common.Address) *Genesis {
	// Override the default period to the user requested one
	config := *params.AllDevChainProtocolChanges

	// Assemble and return the genesis with the precompiles and faucet pre-funded
	genesis := &Genesis{
		Config:     &config,
		GasLimit:   gasLimit,
		BaseFee:    big.NewInt(params.InitialBaseFee),
		Difficulty: big.NewInt(1),
		Alloc: map[common.Address]types.Account{
			common.BytesToAddress([]byte{1}): {Balance: big.NewInt(1)}, // ECRecover
			common.BytesToAddress([]byte{2}): {Balance: big.NewInt(1)}, // SHA256
			common.BytesToAddress([]byte{3}): {Balance: big.NewInt(1)}, // RIPEMD
			common.BytesToAddress([]byte{4}): {Balance: big.NewInt(1)}, // Identity
			common.BytesToAddress([]byte{5}): {Balance: big.NewInt(1)}, // ModExp
			common.BytesToAddress([]byte{6}): {Balance: big.NewInt(1)}, // ECAdd
			common.BytesToAddress([]byte{7}): {Balance: big.NewInt(1)}, // ECScalarMul
			common.BytesToAddress([]byte{8}): {Balance: big.NewInt(1)}, // ECPairing
			common.BytesToAddress([]byte{9}): {Balance: big.NewInt(1)}, // BLAKE2b
		},
	}
	if faucet != nil {
		genesis.Alloc[*faucet] = types.Account{Balance: new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(9))}
	}
	return genesis
}

// DefaultBitlayerL2GenesisBlock returns the Ethereum main net genesis block.
func DefaultBitlayerL2GenesisBlock() *Genesis {
	return &Genesis{
		Config:     params.BitlayerL2MainnetChainConfig,
		Timestamp:  0x660F3F00,
		ExtraData:  hexutil.MustDecode("0x4269746c61796572206d61696e6e6574000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
		GasLimit:   0x2625a00,
		BaseFee:    big.NewInt(10000000),
		Difficulty: big.NewInt(1),
		Alloc:      decodePrealloc(bitlayerL2MainnetAllocData),
		Mixhash:    common.Hash{},
		Validators: []ValidatorInfo{
			makeValidator("0x12a95f3C32E400129C7970f5D490152aD24dD869", "0xEa4B31236F97d569986db5CcA77585140ad1CEe1", "10", true),
			makeValidator("0xcf82d4B3Cb55Cdf9970332793f6a53F09b8dBfE7", "0xEa4B31236F97d569986db5CcA77585140ad1CEe1", "10", true),
			makeValidator("0x2285836a6db6d31485Bd0517ed5D1f975B3d28B3", "0xEa4B31236F97d569986db5CcA77585140ad1CEe1", "10", true),
			makeValidator("0x945F19C1A721f228B7B8403340032C5418aB5601", "0xEa4B31236F97d569986db5CcA77585140ad1CEe1", "10", true),
			makeValidator("0x010825F17B47CCedBF675AC69bCDaD102Dc8B39c", "0xEa4B31236F97d569986db5CcA77585140ad1CEe1", "10", true),
			makeValidator("0x2D7a8b6a249899Aa6763B898f97EeDE505A6fDeC", "0xEa4B31236F97d569986db5CcA77585140ad1CEe1", "10", true),
			makeValidator("0x9B47F90Adee462b43a2F39Fa62824b45bd59d324", "0xEa4B31236F97d569986db5CcA77585140ad1CEe1", "10", true),

			makeValidator("0xe8b500E26216444C01fa703183877CB388F4efa5", "0xEa4B31236F97d569986db5CcA77585140ad1CEe1", "10", true),
			makeValidator("0x481f124523DD08287EAdFBf4e5c827eA7708cE97", "0xEa4B31236F97d569986db5CcA77585140ad1CEe1", "10", true),
			makeValidator("0x42c59AD7941752041012212445DDC005635eaAea", "0xEa4B31236F97d569986db5CcA77585140ad1CEe1", "10", true),
			makeValidator("0x56cB8f58EAd1c8d5066235e17223A49Dc2dC471D", "0xEa4B31236F97d569986db5CcA77585140ad1CEe1", "10", true),
			makeValidator("0x08D0d74874b4bf75525c704f6bd84B071C6D24de", "0xEa4B31236F97d569986db5CcA77585140ad1CEe1", "10", true),
			makeValidator("0x5a3a8F1D14AC18A6a985D7Bc77cb8E1b45f4338D", "0xEa4B31236F97d569986db5CcA77585140ad1CEe1", "10", true),
			makeValidator("0x4bfD5fEd53D0AB9d4A0e212a8064AD9371e53cb8", "0xEa4B31236F97d569986db5CcA77585140ad1CEe1", "10", true),

			makeValidator("0x7069c8642393A63875083a911d7572a2Fe083EA8", "0xEa4B31236F97d569986db5CcA77585140ad1CEe1", "10", true),
			makeValidator("0x6a4987e5809cCF56C80F58619074848250fc5b1D", "0xEa4B31236F97d569986db5CcA77585140ad1CEe1", "10", true),
			makeValidator("0x0Ce657c75048f791b9dA545C2D1f78d053D771cB", "0xEa4B31236F97d569986db5CcA77585140ad1CEe1", "10", true),
			makeValidator("0x0Fac0285011992215EDB080F14A2Cc6Ab629360b", "0xEa4B31236F97d569986db5CcA77585140ad1CEe1", "10", true),
			makeValidator("0xcdeB5Dfbd761CF8bC5619EF5752Aa2a2f2397901", "0xEa4B31236F97d569986db5CcA77585140ad1CEe1", "10", true),
			makeValidator("0x7C56201eaC832562df7190016F39A801CEd39AbB", "0xEa4B31236F97d569986db5CcA77585140ad1CEe1", "10", true),
			makeValidator("0xeb2F2922AF16f42daaeC6d3B485785F064cCB556", "0xEa4B31236F97d569986db5CcA77585140ad1CEe1", "10", true),
		},
	}
}

// DefaultTestnetGenesisBlock returns the Testnet network genesis block.
func DefaultBitlayerL2TestnetGenesisBlock() *Genesis {
	return &Genesis{
		Config:     params.BitlayerL2TestnetChainConfig,
		Timestamp:  0x65BC7F99,
		ExtraData:  hexutil.MustDecode("0x4269746c6179657220746573746e6574000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
		GasLimit:   0x2625a00,
		Difficulty: big.NewInt(1),
		Alloc:      decodePrealloc(bitlayerL2TestnetAllocData),
		Mixhash:    common.Hash{},
		Validators: []ValidatorInfo{
			makeValidator("0x9F01eb5eB4dBEa8B2CeCc679050819990AB68a1A", "0x2e46771cff3636a42f363826ff8a94d3a738e075", "20", true),
			makeValidator("0x2E1CdDC303432F89FFa3c7724De96A9B76242D9D", "0x2e46771cff3636a42f363826ff8a94d3a738e075", "20", true),
			makeValidator("0xbf6dCd00e83058fc361b61BbF31C306BF81a97b2", "0x2e46771cff3636a42f363826ff8a94d3a738e075", "20", true),
		},
	}
}

// BasicMerlionGenesisBlock test only
// BasicMerlionGenesisBlock returns a genesis containing basic allocation for Chais engine,
func BasicMerlionGenesisBlock(config *params.ChainConfig, initialValidators []common.Address, faucet common.Address) *Genesis {
	extraVanity := 32
	extraData := make([]byte, extraVanity+65)
	alloc := decodePrealloc(basicAllocForMerlion)
	if (faucet != common.Address{}) {
		// 100M
		b, _ := new(big.Int).SetString("100000000000000000000000000", 10)
		alloc[faucet] = GenesisAccount{Balance: b}
	}
	alloc[system.StakingContract].Init.Admin = faucet
	alloc[system.StakingContract].Init.Epoch = new(big.Int).SetUint64(config.Merlion.Epoch)

	validators := make([]ValidatorInfo, 0, len(initialValidators))
	for _, val := range initialValidators {
		validators = append(validators, ValidatorInfo{val, faucet, big.NewInt(20), true})
	}

	return &Genesis{
		Config:     config,
		ExtraData:  extraData,
		GasLimit:   0x280de80,
		Difficulty: big.NewInt(2),
		Alloc:      alloc,
		Validators: validators,
	}
}

type initArgs struct {
	Admin          *big.Int
	BtrAddress     *big.Int
	Epoch          *big.Int
	FoundationPool *big.Int
}

func decodePrealloc(data string) GenesisAlloc {
	var p []struct {
		Addr    *big.Int
		Balance *big.Int
		Init    *initArgs
		Misc    *struct {
			Nonce uint64
			Code  []byte
			Slots []struct {
				Key common.Hash
				Val common.Hash
			}
		} `rlp:"optional"`
	}

	if err := rlp.NewStream(strings.NewReader(data), 0).Decode(&p); err != nil {
		return decodePreallocOld(data)
	}
	ga := make(GenesisAlloc, len(p))
	for _, account := range p {
		acc := GenesisAccount{Balance: account.Balance}
		if account.Misc != nil {
			acc.Nonce = account.Misc.Nonce
			acc.Code = account.Misc.Code

			acc.Storage = make(map[common.Hash]common.Hash)
			for _, slot := range account.Misc.Slots {
				acc.Storage[slot.Key] = slot.Val
			}
		}
		if account.Init != nil {
			init := &types.Init{
				Admin:          common.BigToAddress(account.Init.Admin),
				BtrAddress:     common.BigToAddress(account.Init.BtrAddress),
				Epoch:          account.Init.Epoch,
				FoundationPool: common.BigToAddress(account.Init.FoundationPool),
			}
			acc.Init = init
		}
		ga[common.BigToAddress(account.Addr)] = acc
	}
	return ga
}

func decodePreallocOld(data string) GenesisAlloc {
	var p []struct {
		Addr    *big.Int
		Balance *big.Int
		Misc    *struct {
			Nonce uint64
			Code  []byte
			Slots []struct {
				Key common.Hash
				Val common.Hash
			}
		} `rlp:"optional"`
	}

	if err := rlp.NewStream(strings.NewReader(data), 0).Decode(&p); err != nil {
		panic(err)
	}
	ga := make(types.GenesisAlloc, len(p))
	for _, account := range p {
		acc := types.Account{Balance: account.Balance}
		if account.Misc != nil {
			acc.Nonce = account.Misc.Nonce
			acc.Code = account.Misc.Code

			acc.Storage = make(map[common.Hash]common.Hash)
			for _, slot := range account.Misc.Slots {
				acc.Storage[slot.Key] = slot.Val
			}
		}
		ga[common.BigToAddress(account.Addr)] = acc
	}
	return ga
}
