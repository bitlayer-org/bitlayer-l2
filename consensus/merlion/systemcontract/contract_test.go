package systemcontract

import (
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/contracts/system"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/ethereum/go-ethereum/triedb"
	"github.com/holiman/uint256"
	"github.com/stretchr/testify/assert"
)

var GenesisValidators = []common.Address{
	common.HexToAddress("0x2B5AD5c4795c026514f8317c7a215E218DcCD6cF"),
	common.HexToAddress("0x6813Eb9362372EEF6200f3b1dbC3f819671cBA69"),
	common.HexToAddress("0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf"),
}

func TestGetTopValidators(t *testing.T) {
	ctx, err := initCallContext()
	assert.NoError(t, err, "Init call context error")

	vals, err := GetTopValidators(ctx)
	fmt.Printf("val size %d\n", len(vals))
	for i := 0; i < len(vals); i++ {
		fmt.Printf("val %d  %s\n", i, vals[i])
	}
	if assert.NoError(t, err) {
		assert.Equal(t, GenesisValidators, vals)
	}
}

func TestUpdateActiveValidatorSet(t *testing.T) {
	ctx, err := initCallContext()
	assert.NoError(t, err, "Init call context error")

	getActiveValidators := func(ctx *CallContext) []common.Address {
		validators, ok := readSystemContract(t, ctx, "getActiveValidators").([]common.Address)
		assert.True(t, ok, "invalid validator format")
		return validators
	}
	valSet := getActiveValidators(ctx)
	newSet := []common.Address{
		valSet[0],
		valSet[1],
	}

	if assert.NoError(t, UpdateActiveValidatorSet(ctx, newSet)) {
		assert.Equal(t, newSet, getActiveValidators(ctx))
	}
}

func TestDecreaseMissedBlocksCounter(t *testing.T) {
	ctx, err := initCallContext()
	assert.NoError(t, err, "Init call context error")

	getPunishRecord := func(val common.Address) int {
		count, ok := readSystemContract(t, ctx, "getPunishRecord", val).(*big.Int)
		assert.True(t, ok, "invalid result format")
		return int(count.Int64())
	}

	LazyPunish(ctx, GenesisValidators[0])

	assert.Equal(t, 1, getPunishRecord(GenesisValidators[0]))

	assert.NoError(t, DecreaseMissedBlocksCounter(ctx))

	assert.Equal(t, 0, getPunishRecord(GenesisValidators[0]))
}

func TestDistributeBlockFee(t *testing.T) {
	ctx, err := initCallContext()
	assert.NoError(t, err, "Init call context error")

	assert.NoError(t, UpdateActiveValidatorSet(ctx, GenesisValidators))

	feeStaking := ctx.Statedb.GetBalance(system.StakingContract)

	fee := uint256.NewInt(1000000000000000000)
	ctx.Statedb.AddBalance(EngineCaller, fee)
	assert.NoError(t, DistributeBlockFee(ctx, fee))

	feeStakingE := ctx.Statedb.GetBalance(system.StakingContract)

	println("feeStaking ", feeStaking.String(), "feeStakingE", feeStakingE.String())
	assert.Equal(t, feeStaking.Add(feeStaking, fee), feeStakingE)
}

func TestLazyPunish(t *testing.T) {
	ctx, err := initCallContext()
	assert.NoError(t, err, "Init call context error")
	getPunishRecord := func(val common.Address) int {
		count, ok := readSystemContract(t, ctx, "getPunishRecord", val).(*big.Int)
		assert.True(t, ok, "invalid validator format")
		return int(count.Int64())
	}

	assert.Equal(t, 0, getPunishRecord(GenesisValidators[0]))

	assert.NoError(t, LazyPunish(ctx, GenesisValidators[0]))

	assert.Equal(t, 1, getPunishRecord(GenesisValidators[0]))
}

// Utils function to create call context
func initCallContext() (*CallContext, error) {
	file, err := os.Open("../testdata/example.genesis.json")
	if err != nil {
		return nil, err
	}
	defer file.Close()
	genesis := new(core.Genesis)
	if err := json.NewDecoder(file).Decode(genesis); err != nil {
		return nil, err
	}

	db := rawdb.NewMemoryDatabase()
	// genesisBlock := genesis.ToBlock()
	triedb := triedb.NewDatabase(db, triedb.HashDefaults)
	genesisBlock, _ := genesis.Commit(db, triedb)

	fmt.Printf("genesis header hash %s, root %s\n", genesisBlock.Hash().String(), genesisBlock.Root().String())

	header := &types.Header{
		ParentHash: genesisBlock.Hash(),
		Number:     big.NewInt(200),
		Difficulty: common.Big2,
		Time:       uint64(time.Now().Unix()),
		Coinbase:   common.HexToAddress("0x352BbF453fFdcba6b126a73eD684260D7968dDc8"),
	}

	var statedb *state.StateDB
	if statedb, err = state.New(genesisBlock.Root(), state.NewDatabase(db), nil); err != nil {
		return nil, err
	}

	return &CallContext{
		Statedb:      statedb,
		Header:       header,
		ChainContext: &MockChainContext{header, &MockConsensusEngine{}},
		ChainConfig:  genesis.Config,
	}, nil
}

func readSystemContract(t *testing.T, ctx *CallContext, method string, args ...interface{}) interface{} {
	return readContract(t, ctx, &system.StakingContract, method, args...)
}

func readContract(t *testing.T, ctx *CallContext, contract *common.Address, method string, args ...interface{}) interface{} {
	file, err := os.Open("../testdata/staking_abi.json")
	if err != nil {
		panic(err)
	}

	abi, err := abi.JSON(file)
	assert.NoError(t, err)
	// execute contract
	data, err := abi.Pack(method, args...)
	assert.NoError(t, err)

	result, err := CallContract(ctx, contract, data)
	assert.NoError(t, err)

	// unpack data
	ret, err := abi.Unpack(method, result)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(ret), "invalid result length")
	return ret[0]
}

// MockChainContext implements ChainContext for unit test
type MockChainContext struct {
	header *types.Header
	engine consensus.Engine
}

func (c *MockChainContext) Engine() consensus.Engine {
	return c.engine
}

func (c *MockChainContext) GetHeader(common.Hash, uint64) *types.Header {
	return c.header
}

// MockConsensusEngine implements Engine for unit test
type MockConsensusEngine struct {
}

func (c *MockConsensusEngine) Author(header *types.Header) (common.Address, error) {
	return header.Coinbase, nil
}

func (c *MockConsensusEngine) VerifyHeader(chain consensus.ChainHeaderReader, header *types.Header) error {
	return nil
}

func (c *MockConsensusEngine) VerifyHeaders(chain consensus.ChainHeaderReader, headers []*types.Header) (chan<- struct{}, <-chan error) {
	return make(chan struct{}), make(chan error, len(headers))
}

func (c *MockConsensusEngine) VerifyUncles(chain consensus.ChainReader, block *types.Block) error {
	return nil
}

func (c *MockConsensusEngine) Prepare(chain consensus.ChainHeaderReader, header *types.Header) error {
	return nil
}

func (c *MockConsensusEngine) Finalize(chain consensus.ChainHeaderReader, header *types.Header, state *state.StateDB, txs []*types.Transaction, uncles []*types.Header, withdrawals []*types.Withdrawal) error {
	return nil
}
func (c *MockConsensusEngine) FinalizeAndAssemble(chain consensus.ChainHeaderReader, header *types.Header, state *state.StateDB, txs []*types.Transaction, uncles []*types.Header, receipts []*types.Receipt, withdrawals []*types.Withdrawal) (*types.Block, error) {
	return nil, nil
}

func (c *MockConsensusEngine) Seal(chain consensus.ChainHeaderReader, block *types.Block, results chan<- *types.Block, stop <-chan struct{}) error {
	return nil
}

func (c *MockConsensusEngine) CalcDifficulty(chain consensus.ChainHeaderReader, time uint64, parent *types.Header) *big.Int {
	return common.Big2
}

func (c *MockConsensusEngine) SealHash(header *types.Header) common.Hash {
	return common.Hash{}
}

func (c *MockConsensusEngine) Close() error {
	return nil
}

func (c *MockConsensusEngine) APIs(chain consensus.ChainHeaderReader) []rpc.API {
	return []rpc.API{}
}
