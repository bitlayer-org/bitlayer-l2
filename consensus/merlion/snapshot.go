// Copyright 2017 The go-ethereum Authors
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

package merlion

import (
	"encoding/json"
	"sort"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/merlion/systemcontract"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/params"
	lru "github.com/hashicorp/golang-lru"
)

// Snapshot is the state of the authorization voting at a given point in time.
type Snapshot struct {
	config   *params.ChainConfig // Consensus engine parameters to fine tune behavior
	sigcache *lru.ARCCache       // Cache of recent block signatures to speed up ecrecover

	Number     uint64                      `json:"number"`     // Block number where the snapshot was created
	Hash       common.Hash                 `json:"hash"`       // Block hash where the snapshot was created
	Validators map[common.Address]struct{} `json:"validators"` // Set of authorized validators at this moment
	Recents    map[uint64]common.Address   `json:"recents"`    // Set of recent validators for spam protections
}

// newSnapshot creates a new snapshot with the specified startup parameters. This
// method does not initialize the set of recent validators, so only ever use if for
// the genesis block.
func newSnapshot(config *params.ChainConfig, sigcache *lru.ARCCache, number uint64, hash common.Hash, validators []common.Address) *Snapshot {
	snap := &Snapshot{
		config:     config,
		sigcache:   sigcache,
		Number:     number,
		Hash:       hash,
		Validators: make(map[common.Address]struct{}),
		Recents:    make(map[uint64]common.Address),
	}
	for _, validator := range validators {
		snap.Validators[validator] = struct{}{}
	}
	return snap
}

// loadSnapshot loads an existing snapshot from the database.
func loadSnapshot(config *params.ChainConfig, sigcache *lru.ARCCache, db ethdb.Database, hash common.Hash) (*Snapshot, error) {
	blob, err := db.Get(append([]byte("merlion-"), hash[:]...))
	if err != nil {
		return nil, err
	}
	snap := new(Snapshot)
	if err := json.Unmarshal(blob, snap); err != nil {
		return nil, err
	}
	snap.config = config
	snap.sigcache = sigcache

	return snap, nil
}

// store inserts the snapshot into the database.
func (s *Snapshot) store(db ethdb.Database) error {
	blob, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return db.Put(append([]byte("merlion-"), s.Hash[:]...), blob)
}

// copy creates a deep copy of the snapshot, though not the individual votes.
func (s *Snapshot) copy() *Snapshot {
	cpy := &Snapshot{
		config:     s.config,
		sigcache:   s.sigcache,
		Number:     s.Number,
		Hash:       s.Hash,
		Validators: make(map[common.Address]struct{}),
		Recents:    make(map[uint64]common.Address),
	}
	for validator := range s.Validators {
		cpy.Validators[validator] = struct{}{}
	}
	for block, validator := range s.Recents {
		cpy.Recents[block] = validator
	}

	return cpy
}

// SignedRecently checks whether the validator signed block recently
func (s *Snapshot) SignedRecently(block uint64, validator common.Address) bool {
	limit := uint64(len(s.Validators)/2 + 1)
	for blockNum, recent := range s.Recents {
		if blockNum > block-limit && recent == validator {
			return true
		}
	}
	return false
}

// apply creates a new authorization snapshot by applying the given headers to
// the original one.
func (s *Snapshot) apply(headers []*types.Header, chain consensus.ChainHeaderReader, parents []*types.Header) (*Snapshot, error) {
	// Allow passing in no headers for cleaner code
	if len(headers) == 0 {
		return s, nil
	}
	// Sanity check that the headers can be applied
	for i := 0; i < len(headers)-1; i++ {
		if headers[i+1].Number.Uint64() != headers[i].Number.Uint64()+1 {
			return nil, errInvalidVotingChain
		}
	}
	if headers[0].Number.Uint64() != s.Number+1 {
		return nil, errInvalidVotingChain
	}
	// Iterate through the headers and create a new snapshot
	snap := s.copy()

	for i, header := range headers {
		// Remove any votes on checkpoint blocks
		number := header.Number.Uint64()
		if limit := uint64(len(snap.Validators)/2 + 1); number >= limit {
			// Delete the oldest validator from the recent list to allow it signing again
			delete(snap.Recents, number-limit)
		}
		// Resolve the authorization key and check against validators
		validator, err := ecrecover(header, s.sigcache)
		if err != nil {
			return nil, err
		}
		if _, ok := snap.Validators[validator]; !ok {
			return nil, errUnauthorizedValidator
		}
		if snap.SignedRecently(number, validator) {
			return nil, errRecentlySigned
		}
		snap.Recents[number] = validator

		// update validators at the first block at epoch
		// use a look-back validators set for Merlion.
		// That is: the blocks in the first two epoch will use the genesis validators;
		// the blocks ≥ 2*EpochPeriod + 1 are using the look-back validators set.
		if number > 0 && number%s.config.Merlion.Epoch == 0 {
			var checkpointHeader *types.Header
			// For a large chain insertion, the previous blocks may not have been written to db,
			// so we need to find it through both previous `headers` and parents
			if uint64(i) >= s.config.Merlion.Epoch {
				checkpointHeader = headers[i-int(s.config.Merlion.Epoch)]
			} else {
				// i < epoch ==> epoch -i >= 1
				idxInParents := len(parents) - (int(s.config.Merlion.Epoch) - i)
				if idxInParents >= 0 {
					checkpointHeader = parents[idxInParents]
				} else {
					checkpointHeader = chain.GetHeaderByNumber(number - s.config.Merlion.Epoch)
					if checkpointHeader == nil {
						return nil, consensus.ErrUnknownAncestor
					}
				}
			}

			// get validators from headers and use that for new validator set
			validators := make([]common.Address, (len(checkpointHeader.Extra)-extraVanity-extraSeal)/common.AddressLength)
			for i := 0; i < len(validators); i++ {
				copy(validators[i][:], checkpointHeader.Extra[extraVanity+i*common.AddressLength:])
			}

			newValidators := make(map[common.Address]struct{})
			for _, validator := range validators {
				newValidators[validator] = struct{}{}
			}

			// need to delete recorded recent seen blocks if necessary, it may pause whole chain when validators length
			// decreases.
			limit := uint64(len(newValidators)/2 + 1)
			for i := 0; i < (len(snap.Validators)/2 - len(newValidators)/2); i++ {
				delete(snap.Recents, number-limit-uint64(i))
			}

			snap.Validators = newValidators
		}
	}

	snap.Number += uint64(len(headers))
	snap.Hash = headers[len(headers)-1].Hash()

	return snap, nil
}

// validators retrieves the list of authorized validators in ascending order.
func (s *Snapshot) validators() []common.Address {
	sigs := make([]common.Address, 0, len(s.Validators))
	for sig := range s.Validators {
		sigs = append(sigs, sig)
	}
	sort.Sort(systemcontract.AddrAscend(sigs))
	return sigs
}

// inturn returns if a validator at a given block height is in-turn or not.
func (s *Snapshot) inturn(number uint64, validator common.Address) bool {
	validators, offset := s.validators(), 0
	for offset < len(validators) && validators[offset] != validator {
		offset++
	}
	return (number % (uint64(len(validators)))) == uint64(offset)
}

func (s *Snapshot) IsAuthorized(addr common.Address) bool {
	_, exist := s.Validators[addr]
	return exist
}

func (s *Snapshot) Len() int {
	return len(s.Validators)
}
