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

package rpow

import (
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/usechain/go-usechain/common"
	"github.com/usechain/go-usechain/common/math"
	"github.com/usechain/go-usechain/consensus"
	"github.com/usechain/go-usechain/consensus/misc"
	"github.com/usechain/go-usechain/contracts/minerlist"
	"github.com/usechain/go-usechain/core/state"
	"github.com/usechain/go-usechain/core/types"
	"github.com/usechain/go-usechain/crypto/sha3"
	"github.com/usechain/go-usechain/params"
	"gopkg.in/fatih/set.v0"
	"math/big"
	"runtime"
	"strings"
	"time"
)

// random-proof-of-work protocol constants.
var (
	// Block reward in hui for successfully mining a block upward from Sapphir
	SapphireBlockReward *big.Int = big.NewInt(0).Mul(big.NewInt(1e+18), big.NewInt(15))
	// Maximum number of uncles allowed in a single block
	maxUncles = 0
	// Max time from current time allowed for blocks, before they're considered future blocks
	allowedFutureBlockTime = 15 * time.Second
	// paramIndex Head
	paramIndexHead = "000000000000000000000000"
)

// Genesis difficulty
var (
	CommonDifficulty = big.NewInt(1)
)

// Various error messages to mark blocks invalid. These should be private to
// prevent engine specific errors from being referenced in the remainder of the
// codebase, inherently breaking if the engine is swapped out. Please put common
// error types into the consensus package.
var (
	errLargeBlockTime    = errors.New("timestamp too big")
	errZeroBlockTime     = errors.New("timestamp equals parent's")
	errTooManyUncles     = errors.New("too many uncles")
	errDuplicateUncle    = errors.New("duplicate uncle")
	errUncleIsAncestor   = errors.New("uncle is ancestor")
	errDanglingUncle     = errors.New("uncle's parent is not ancestor")
	errInvalidDifficulty = errors.New("non-positive difficulty")
	errInvalidMixDigest  = errors.New("invalid mix digest")
	errInvalidRpow       = errors.New("invalid rpow")
)

// Author implements consensus.Engine, returning the header's coinbase as the
// rpow verified author of the block.
func (rpow *Rpow) Author(header *types.Header) (common.Address, error) {
	return header.Coinbase, nil
}

// VerifyHeader checks whether a header conforms to the consensus rules of the
// stock Usechain rpow engine.
func (rpow *Rpow) VerifyHeader(chain consensus.ChainReader, header *types.Header, seal bool, state *state.StateDB) error {
	// If we're running a full engine faking, accept any input as valid
	if rpow.config.RpowMode == ModeFullFake {
		return nil
	}
	// Short circuit if the header is known, or it's parent not
	number := header.Number.Uint64()
	if chain.GetHeader(header.Hash(), number) != nil {
		return nil
	}
	parent := chain.GetHeader(header.ParentHash, number-1)
	if parent == nil {
		return consensus.ErrUnknownAncestor
	}
	// Sanity checks passed, do a proper verification
	return rpow.verifyHeader(chain, header, parent, false, seal, state)
}

// VerifyHeaders is similar to VerifyHeader, but verifies a batch of headers
// concurrently. The method returns a quit channel to abort the operations and
// a results channel to retrieve the async verifications.
func (rpow *Rpow) VerifyHeaders(chain consensus.ChainReader, headers []*types.Header, seals []bool, state *state.StateDB) (chan<- struct{}, <-chan error) {
	// If we're running a full engine faking, accept any input as valid
	if rpow.config.RpowMode == ModeFullFake || len(headers) == 0 {
		abort, results := make(chan struct{}), make(chan error, len(headers))
		for i := 0; i < len(headers); i++ {
			results <- nil
		}
		return abort, results
	}

	// Spawn as many workers as allowed threads
	workers := runtime.GOMAXPROCS(0)
	if len(headers) < workers {
		workers = len(headers)
	}

	// Create a task channel and spawn the verifiers
	var (
		inputs = make(chan int)
		done   = make(chan int, workers)
		errors = make([]error, len(headers))
		abort  = make(chan struct{})
	)
	for i := 0; i < workers; i++ {
		go func() {
			for index := range inputs {
				errors[index] = rpow.verifyHeaderWorker(chain, headers, seals, index, state)
				done <- index
			}
		}()
	}

	errorsOut := make(chan error, len(headers))
	go func() {
		defer close(inputs)
		var (
			in, out = 0, 0
			checked = make([]bool, len(headers))
			inputs  = inputs
		)
		for {
			select {
			case inputs <- in:
				if in++; in == len(headers) {
					// Reached end of headers. Stop sending to workers.
					inputs = nil
				}
			case index := <-done:
				for checked[index] = true; checked[out]; out++ {
					errorsOut <- errors[out]
					if out == len(headers)-1 {
						return
					}
				}
			case <-abort:
				return
			}
		}
	}()
	return abort, errorsOut
}

func (rpow *Rpow) verifyHeaderWorker(chain consensus.ChainReader, headers []*types.Header, seals []bool, index int, state *state.StateDB) error {
	var parent *types.Header
	if index == 0 {
		parent = chain.GetHeader(headers[0].ParentHash, headers[0].Number.Uint64()-1)
	} else if headers[index-1].Hash() == headers[index].ParentHash {
		parent = headers[index-1]
	}
	if parent == nil {
		return consensus.ErrUnknownAncestor
	}
	if chain.GetHeader(headers[index].Hash(), headers[index].Number.Uint64()) != nil {
		return nil // known block
	}
	return rpow.verifyHeader(chain, headers[index], parent, false, seals[index], state)
}

// VerifyUncles verifies that the given block's uncles conform to the consensus
// rules of the stock Usechain rpow engine.
func (rpow *Rpow) VerifyUncles(chain consensus.ChainReader, block *types.Block, state *state.StateDB) error {
	// If we're running a full engine faking, accept any input as valid
	if rpow.config.RpowMode == ModeFullFake {
		return nil
	}
	// Verify that there are at most 2 uncles included in this block
	if len(block.Uncles()) > maxUncles {
		return errTooManyUncles
	}
	// Gather the set of past uncles and ancestors
	uncles, ancestors := set.New(), make(map[common.Hash]*types.Header)

	number, parent := block.NumberU64()-1, block.ParentHash()
	for i := 0; i < 7; i++ {
		ancestor := chain.GetBlock(parent, number)
		if ancestor == nil {
			break
		}
		ancestors[ancestor.Hash()] = ancestor.Header()
		for _, uncle := range ancestor.Uncles() {
			uncles.Add(uncle.Hash())
		}
		parent, number = ancestor.ParentHash(), number-1
	}
	ancestors[block.Hash()] = block.Header()
	uncles.Add(block.Hash())

	// Verify each of the uncles that it's recent, but not an ancestor
	for _, uncle := range block.Uncles() {
		// Make sure every uncle is rewarded only once
		hash := uncle.Hash()
		if uncles.Has(hash) {
			return errDuplicateUncle
		}
		uncles.Add(hash)

		// Make sure the uncle has a valid ancestry
		if ancestors[hash] != nil {
			return errUncleIsAncestor
		}
		if ancestors[uncle.ParentHash] == nil || uncle.ParentHash == block.ParentHash() {
			return errDanglingUncle
		}
		if err := rpow.verifyHeader(chain, uncle, ancestors[uncle.ParentHash], true, true, state); err != nil {
			return err
		}
	}
	return nil
}

// verifyHeader checks whether a header conforms to the consensus rules of the
// stock Usechain rpow engine.
// See YP section 4.3.4. "Block Header Validity"
func (rpow *Rpow) verifyHeader(chain consensus.ChainReader, header, parent *types.Header, uncle bool, seal bool, state *state.StateDB) error {
	// Ensure that the header's extra-data section is of a reasonable size
	if uint64(len(header.Extra)) > params.MaximumExtraDataSize {
		return fmt.Errorf("extra-data too long: %d > %d", len(header.Extra), params.MaximumExtraDataSize)
	}
	// Verify the header's timestamp
	if uncle {
		if header.Time.Cmp(math.MaxBig256) > 0 {
			return errLargeBlockTime
		}
	} else {
		if header.Time.Cmp(big.NewInt(time.Now().Add(allowedFutureBlockTime).Unix())) > 0 {
			return consensus.ErrFutureBlock
		}
	}
	if header.Time.Cmp(parent.Time) <= 0 {
		return errZeroBlockTime
	}

	// Verify the block's difficulty based in it's timestamp and parent's difficulty
	expected := rpow.CalcDifficulty(chain, header.Time.Uint64(), header, parent)

	if expected.Cmp(header.Difficulty) != 0 {
		return fmt.Errorf("invalid difficulty: have %v, want %v", header.Difficulty, expected)
	}
	// Verify that the gas limit is <= 2^63-1
	cap := uint64(0x7fffffffffffffff)
	if header.GasLimit > cap {
		return fmt.Errorf("invalid gasLimit: have %v, max %v", header.GasLimit, cap)
	}
	// Verify that the gasUsed is <= gasLimit
	if header.GasUsed > header.GasLimit {
		return fmt.Errorf("invalid gasUsed: have %d, gasLimit %d", header.GasUsed, header.GasLimit)
	}

	// Verify that the gas limit remains within allowed bounds
	diff := int64(parent.GasLimit) - int64(header.GasLimit)
	if diff < 0 {
		diff *= -1
	}
	limit := parent.GasLimit / params.GasLimitBoundDivisor

	if uint64(diff) >= limit || header.GasLimit < params.MinGasLimit {
		return fmt.Errorf("invalid gas limit: have %d, want %d += %d", header.GasLimit, parent.GasLimit, limit)
	}
	// Verify that the block number is parent's +1
	if diff := new(big.Int).Sub(header.Number, parent.Number); diff.Cmp(big.NewInt(1)) != 0 {
		return consensus.ErrInvalidNumber
	}
	// Verify the engine specific seal securing the block
	if seal {
		if err := rpow.VerifySeal(chain, header); err != nil {
			return err
		}
	}
	// If all checks passed, validate any special fields for hard forks
	if err := misc.VerifyDAOHeaderExtraData(chain.Config(), header); err != nil {
		return err
	}
	if err := misc.VerifyForkHashes(chain.Config(), header, uncle); err != nil {
		return err
	}
	return nil
}

/*
 * CalcDifficulty is the difficulty adjustment algorithm. It returns
 * the difficulty that a new block should have when created at time
 * given the parent block's time and difficulty.
 */
func (rpow *Rpow) CalcDifficulty(chain consensus.ChainReader, time uint64, header *types.Header, parent *types.Header) *big.Int {
	return CommonDifficulty
}

// Some weird constants to avoid constant memory allocs for them.
var (
	expDiffPeriod = big.NewInt(100000)
	big1          = big.NewInt(1)
	big2          = big.NewInt(2)
	big9          = big.NewInt(9)
	big10         = big.NewInt(10)
	big20         = big.NewInt(20)
	bigMinus99    = big.NewInt(-99)
	big2999999    = big.NewInt(2999999)
)

// VerifySeal implements consensus.Engine, checking whether the given block satisfies
// the Rpow difficulty requirements.
func (rpow *Rpow) VerifySeal(chain consensus.ChainReader, header *types.Header) error {
	// If we're running a fake PoW, accept any seal as valid
	if rpow.config.RpowMode == ModeFake || rpow.config.RpowMode == ModeFullFake {
		time.Sleep(rpow.fakeDelay)
		if rpow.fakeFail == header.Number.Uint64() {
			return errInvalidRpow
		}
		return nil
	}
	// If we're running a shared PoW, delegate verification to it
	if rpow.shared != nil {
		return rpow.shared.VerifySeal(chain, header)
	}
	// Ensure that we have a valid difficulty for the block
	if header.Difficulty.Sign() <= 0 {
		return errInvalidDifficulty
	}
	return nil
}

// Prepare implements consensus.Engine, initializing the difficulty field of a
// header to conform to the pow protocol. The changes are done inline.
func (rpow *Rpow) Prepare(chain consensus.ChainReader, header *types.Header, state *state.StateDB) error {
	parent := chain.GetHeader(header.ParentHash, header.Number.Uint64()-1)
	if parent == nil {
		return consensus.ErrUnknownAncestor
	}
	header.Difficulty = rpow.CalcDifficulty(chain, header.Time.Uint64(), header, parent)
	return nil
}

// Finalize implements consensus.Engine, accumulating the block and uncle rewards,
// setting the final state and assembling the block.
func (rpow *Rpow) Finalize(chain consensus.ChainReader, header *types.Header, state *state.StateDB, txs []*types.Transaction, uncles []*types.Header, receipts []*types.Receipt) (*types.Block, error) {
	// Accumulate any block and uncle rewards and commit the final state root
	accumulateRewards(chain.Config(), state, header, uncles)
	handleMisconducts(state, header)
	header.Root = state.IntermediateRoot(chain.Config().IsEIP158(header.Number))

	// Header seems complete, assemble into a block and return
	return types.NewBlock(header, txs, uncles, receipts), nil
}

// Some weird constants to avoid constant memory allocs for them.
var (
	big8  = big.NewInt(8)
	big32 = big.NewInt(32)
)

// AccumulateRewards credits the coinbase of the given block with the mining
// reward. The total reward consists of the static block reward and rewards for
// included uncles. The coinbase of each uncle block is also rewarded.
func accumulateRewards(config *params.ChainConfig, state *state.StateDB, header *types.Header, uncles []*types.Header) {
	// Select the correct block reward based on chain progression
	blockReward := SapphireBlockReward

	// Accumulate the rewards for the miner and any included uncles
	reward := new(big.Int).Set(blockReward)
	r := new(big.Int)
	for _, uncle := range uncles {
		r.Add(uncle.Number, big8)
		r.Sub(r, header.Number)
		r.Mul(r, blockReward)
		r.Div(r, big8)
		state.AddBalance(uncle.Coinbase, r)

		r.Div(blockReward, big32)
		reward.Add(reward, r)
	}
	state.AddBalance(header.Coinbase, reward)
}

// handleMisconducts will check the block whether be mined by PrimaryMiner
// if does, the PrimaryMiner's misconduct count recorded in minelist contract will -1
// if not, the PrimaryMiner's misconduct count recorded in minelist contract will +5
// when the misconduct count reached the MisconductLimit which record in contract
// with default 100, the miner will lose mining right
func handleMisconducts(state *state.StateDB, header *types.Header) {
	priAddr := header.PrimaryMiner
	if !strings.EqualFold(priAddr.String(), header.Coinbase.String()) {
		recordMisconduct(state, priAddr, false, header.Number)
	} else {
		recordMisconduct(state, priAddr, true, header.Number)
	}
}

// recordMisconduct will read & make the misconduct count +5
// correct primary miner will decrease the misconduct count -1
func recordMisconduct(state *state.StateDB, address common.Address, reward bool, blockNumber *big.Int) {
	web3key := paramIndexHead + address.Hex()[2:] + common.BigToHash(big.NewInt(4)).Hex()[2:]
	hash := sha3.NewKeccak256()

	var keyIndex []byte
	b, _ := hex.DecodeString(web3key)
	hash.Write(b)
	keyIndex = hash.Sum(keyIndex)

	// get data from the contract statedb
	res := state.GetState(common.HexToAddress(minerlist.MinerListContract), common.BytesToHash(keyIndex))
	if !reward {
		// add publish to the address with +5
		state.SetState(common.HexToAddress(minerlist.MinerListContract), common.BytesToHash(keyIndex), res.IncreaseHex(big.NewInt(5)))
		if res.Big().Int64() < common.MisconductLimitsLevel1 && res.Big().Int64()+5 >= common.MisconductLimitsLevel1 || res.Big().Int64() < common.MisconductLimitsLevel2 && res.Big().Int64()+5 >= common.MisconductLimitsLevel2 {
			recordPunishHeight(state, address, blockNumber)
		}
	} else {
		// add reward to the address with -1
		if res.Big().Cmp(common.Big0) > 0 {
			state.SetState(common.HexToAddress(minerlist.MinerListContract), common.BytesToHash(keyIndex), res.DecreaseHex(big.NewInt(1)))
		}
	}
}

func recordPunishHeight(state *state.StateDB, address common.Address, blockNumber *big.Int) {
	web3key := paramIndexHead + address.Hex()[2:] + common.BigToHash(big.NewInt(6)).Hex()[2:]
	hash := sha3.NewKeccak256()

	var keyIndex []byte
	b, _ := hex.DecodeString(web3key)
	hash.Write(b)
	keyIndex = hash.Sum(keyIndex)

	state.SetState(common.HexToAddress(minerlist.MinerListContract), common.BytesToHash(keyIndex), common.BigToHash(blockNumber))
}
