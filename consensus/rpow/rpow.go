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

// Package rpow implements the random-proof-of-work consensus engine.
package rpow

import (
	"math/rand"
	"sync"
	"time"

	"github.com/usechain/go-usechain/consensus"
	"github.com/usechain/go-usechain/rpc"
	"github.com/usechain/go-usechain/ethdb"
)

// Mode defines the type and amount of PoW verification a rpow engine makes.
type Mode uint

const (
	ModeNormal Mode = iota
	ModeShared
	ModeTest
	ModeFake
	ModeFullFake
)

// Config are the configuration parameters of the rpow.
type Config struct {
	RpowMode        Mode
}

// Rpow is a consensus engine based on proot-of-work implementing the rpow
// algorithm.
type Rpow struct {
	config Config

	// Mining related fields
	rand     *rand.Rand    // Properly seeded random source for nonces
	threads  int           // Number of threads to mine on if mining
	update   chan struct{} // Notification channel to update mining parameters

	// The fields below are hooks for testing
	shared    *Rpow         // Shared RPoW verifier to avoid cache regeneration
	fakeFail  uint64        // Block number which fails PoW check even in fake mode
	fakeDelay time.Duration // Time delay to sleep for before returning from verify

	lock sync.Mutex // Ensures thread safety for the in-memory caches and mining fields

	db      ethdb.Database
}

// New creates a full sized rpow scheme.
func New(config Config) *Rpow {
	return &Rpow{
		config:   config,
		update:   make(chan struct{}),
	}
}

// NewTester creates a small sized rpow scheme useful only for testing
// purposes.
func NewTester() *Rpow {
	return New(Config{RpowMode: ModeTest})
}

func NewTesterUse(db ethdb.Database) *Rpow {
	return &Rpow{
		config:Config{RpowMode: ModeFake},
		update:      make(chan struct{}),
		db:          db,
	}

	//return NewWithCfg(Config{CachesInMem: 1, RpowMode: ModeTest})
}

// NewFaker creates a rpow consensus engine with a fake PoW scheme that accepts
// all blocks' seal as valid, though they still have to conform to the Ethereum
// consensus rules.
func NewFaker() *Rpow {
	return &Rpow{
		config: Config{
			RpowMode: ModeFake,
		},
	}
}

// NewFakerUsechain creates a rpow consensus engine with a fake PoW scheme that accepts
// all blocks' seal as valid, though they still have to conform to the Ethereum
// consensus rules.
func NewFakerUsechain(db ethdb.Database) *Rpow {
	return &Rpow{
		config: Config{
			RpowMode: ModeFake,
		},
		db:       db,
	}
}

// NewFakeFailer creates a rpow consensus engine with a fake PoW scheme that
// accepts all blocks as valid apart from the single one specified, though they
// still have to conform to the Ethereum consensus rules.
func NewFakeFailer(fail uint64) *Rpow {
	return &Rpow{
		config: Config{
			RpowMode: ModeFake,
		},
		fakeFail: fail,
	}
}

// NewFakeDelayer creates a rpow consensus engine with a fake PoW scheme that
// accepts all blocks as valid, but delays verifications by some time, though
// they still have to conform to the Ethereum consensus rules.
func NewFakeDelayer(delay time.Duration) *Rpow {
	return &Rpow{
		config: Config{
			RpowMode: ModeFake,
		},
		fakeDelay: delay,
	}
}

// NewFullFaker creates a rpow consensus engine with a full fake scheme that
// accepts all blocks as valid, without checking any consensus rules whatsoever.
func NewFullFaker() *Rpow {
	return &Rpow{
		config: Config{
			RpowMode: ModeFullFake,
		},
	}
}

// NewFullFakerUse creates a rpow consensus engine with a full fake scheme that
// accepts all blocks as valid, without checking any consensus rules whatsoever.
func NewFullFakerUse(db ethdb.Database) *Rpow {
	return &Rpow{
		config: Config{
			RpowMode: ModeFullFake,
		},
		db: db,
	}
}

// Threads returns the number of mining threads currently enabled. This doesn't
// necessarily mean that mining is running!
func (rpow *Rpow) Threads() int {
	rpow.lock.Lock()
	defer rpow.lock.Unlock()

	return rpow.threads
}

// SetThreads updates the number of mining threads currently enabled. Calling
// this method does not start mining, only sets the thread count. If zero is
// specified, the miner will use all cores of the machine. Setting a thread
// count below zero is allowed and will cause the miner to idle, without any
// work being done.
func (rpow *Rpow) SetThreads(threads int) {
	rpow.lock.Lock()
	defer rpow.lock.Unlock()

	// If we're running a shared PoW, set the thread count on that instead
	if rpow.shared != nil {
		rpow.shared.SetThreads(threads)
		return
	}
	// Update the threads and ping any running seal to pull in any changes
	rpow.threads = threads
	select {
	case rpow.update <- struct{}{}:
	default:
	}
}

// APIs implements consensus.Engine, returning the user facing RPC APIs. Currently
// that is empty.
func (rpow *Rpow) APIs(chain consensus.ChainReader) []rpc.API {
	return nil
}

// SeedHash is the seed to use for generating a verification cache and the mining
// dataset.
func SeedHash(block uint64) []byte {
	return seedHash(block)
}
