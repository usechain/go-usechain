// Copyright 2015 The go-ethereum Authors
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

package miner

import (
	"fmt"
	"math"
	"math/big"
	"sync"
	"sync/atomic"
	"time"

	"bytes"
	"github.com/usechain/go-usechain/accounts"
	"github.com/usechain/go-usechain/common"
	"github.com/usechain/go-usechain/consensus"
	"github.com/usechain/go-usechain/contracts/minerlist"
	"github.com/usechain/go-usechain/core"
	"github.com/usechain/go-usechain/core/state"
	"github.com/usechain/go-usechain/core/types"
	"github.com/usechain/go-usechain/core/vm"
	"github.com/usechain/go-usechain/ethdb"
	"github.com/usechain/go-usechain/event"
	"github.com/usechain/go-usechain/log"
	"github.com/usechain/go-usechain/params"
	"gopkg.in/fatih/set.v0"
)

const (
	resultQueueSize  = 10
	miningLogAtDepth = 5

	// txChanSize is the size of channel listening to NewTxsEvent.
	// The number is referenced from the size of tx pool.
	txChanSize = 4096 * 16
	// chainHeadChanSize is the size of channel listening to ChainHeadEvent.
	chainHeadChanSize = 10
	// chainSideChanSize is the size of channel listening to ChainSideEvent.
	chainSideChanSize = 10
	// chainRpowChanSize is the size of channel listening to rpow mining event
	chainRpowChanSize = 10
)

// Agent can register themself with the worker
type Agent interface {
	Work() chan<- *Work
	SetReturnCh(chan<- *Result)
	Stop()
	Start()
}

// Work is the workers current environment and holds
// all of the current state information
type Work struct {
	config *params.ChainConfig
	signer types.Signer

	state     *state.StateDB // apply state changes here
	ancestors *set.Set       // ancestor set (used for checking uncle parent validity)
	family    *set.Set       // family set (used for checking uncle invalidity)
	uncles    *set.Set       // uncle set
	tcount    int            // tx count in cycle

	Block *types.Block // the new block

	header   *types.Header
	txs      []*types.Transaction
	receipts []*types.Receipt

	createdAt time.Time
}

type Result struct {
	Work  *Work
	Block *types.Block
}

// worker is the main object which takes care of applying messages to the new state
type worker struct {
	config *params.ChainConfig
	engine consensus.Engine

	mu sync.Mutex

	// update loop
	mux          *event.TypeMux
	txsCh        chan core.NewTxsEvent
	txsSub       event.Subscription
	chainHeadCh  chan core.ChainHeadEvent
	chainHeadSub event.Subscription
	chainSideCh  chan core.ChainSideEvent
	chainSideSub event.Subscription
	chainRpowCh  chan core.ChainRpowEvent
	chainRpowSub event.Subscription
	wg           sync.WaitGroup

	agents map[Agent]struct{}
	recv   chan *Result

	eth     Backend
	chain   *core.BlockChain
	proc    core.Validator
	chainDb ethdb.Database

	coinbase common.Address
	extra    []byte

	currentMu sync.Mutex
	current   *Work

	uncleMu        sync.Mutex
	possibleUncles map[common.Hash]*types.Block

	unconfirmed *unconfirmedBlocks // set of locally mined blocks pending canonicalness confirmations

	// atomic status counters
	mining int32
	atWork int32
}

func newWorker(config *params.ChainConfig, engine consensus.Engine, coinbase common.Address, eth Backend, mux *event.TypeMux) *worker {
	worker := &worker{
		config:         config,
		engine:         engine,
		eth:            eth,
		mux:            mux,
		txsCh:          make(chan core.NewTxsEvent, txChanSize),
		chainHeadCh:    make(chan core.ChainHeadEvent, chainHeadChanSize),
		chainSideCh:    make(chan core.ChainSideEvent, chainSideChanSize),
		chainRpowCh:    make(chan core.ChainRpowEvent, chainRpowChanSize),
		chainDb:        eth.ChainDb(),
		recv:           make(chan *Result, resultQueueSize),
		chain:          eth.BlockChain(),
		proc:           eth.BlockChain().Validator(),
		possibleUncles: make(map[common.Hash]*types.Block),
		coinbase:       coinbase,
		agents:         make(map[Agent]struct{}),
		unconfirmed:    newUnconfirmedBlocks(eth.BlockChain(), miningLogAtDepth),
	}
	// Subscribe NewTxsEvent for tx pool
	worker.txsSub = eth.TxPool().SubscribeNewTxsEvent(worker.txsCh)
	// Subscribe events for blockchain
	worker.chainHeadSub = eth.BlockChain().SubscribeChainHeadEvent(worker.chainHeadCh)
	worker.chainSideSub = eth.BlockChain().SubscribeChainSideEvent(worker.chainSideCh)
	worker.chainRpowSub = eth.BlockChain().SubscribeChainRpowEvent(worker.chainRpowCh)
	go worker.update()

	go worker.wait()
	worker.commitNewWork()

	return worker
}

func (self *worker) setUsebase(addr common.Address) {
	self.mu.Lock()
	defer self.mu.Unlock()
	self.coinbase = addr
}

func (self *worker) setExtra(extra []byte) {
	self.mu.Lock()
	defer self.mu.Unlock()
	self.extra = extra
}

func (self *worker) pending() (*types.Block, *state.StateDB) {
	self.currentMu.Lock()
	defer self.currentMu.Unlock()

	if atomic.LoadInt32(&self.mining) == 0 {
		return types.NewBlock(
			self.current.header,
			self.current.txs,
			nil,
			self.current.receipts,
		), self.current.state.Copy()
	}
	return self.current.Block, self.current.state.Copy()
}

func (self *worker) pendingBlock() *types.Block {
	self.currentMu.Lock()
	defer self.currentMu.Unlock()

	if atomic.LoadInt32(&self.mining) == 0 {
		return types.NewBlock(
			self.current.header,
			self.current.txs,
			nil,
			self.current.receipts,
		)
	}
	return self.current.Block
}

func (self *worker) start() {
	self.mu.Lock()
	defer self.mu.Unlock()

	atomic.StoreInt32(&self.mining, 1)

	// spin up agents
	for agent := range self.agents {
		agent.Start()
	}
}

func (self *worker) stop() {
	self.wg.Wait()

	self.mu.Lock()
	defer self.mu.Unlock()
	if atomic.LoadInt32(&self.mining) == 1 {
		for agent := range self.agents {
			agent.Stop()
		}
	}
	atomic.StoreInt32(&self.mining, 0)
	atomic.StoreInt32(&self.atWork, 0)
}

func (self *worker) register(agent Agent) {
	self.mu.Lock()
	defer self.mu.Unlock()
	self.agents[agent] = struct{}{}
	agent.SetReturnCh(self.recv)
}

func (self *worker) unregister(agent Agent) {
	self.mu.Lock()
	defer self.mu.Unlock()
	delete(self.agents, agent)
	agent.Stop()
}

func (self *worker) update() {
	defer self.txsSub.Unsubscribe()
	defer self.chainHeadSub.Unsubscribe()
	defer self.chainSideSub.Unsubscribe()
	defer self.chainRpowSub.Unsubscribe()

	for {
		// A real event arrived, process interesting content
		select {
		// Handle ChainHeadEvent
		case <-self.chainHeadCh:
			self.commitNewWork()

			// Handle ChainSideEvent
		case ev := <-self.chainSideCh:
			self.uncleMu.Lock()
			self.possibleUncles[ev.Block.Hash()] = ev.Block
			self.uncleMu.Unlock()

		case <-self.chainRpowCh:
			self.commitNewWork()

			// Handle NewTxsEvent
		case ev := <-self.txsCh:
			// Apply transactions to the pending state if we're not mining.
			//
			// Note all transactions received may not be continuous with transactions
			// already included in the current mining block. These transactions will
			// be automatically eliminated.
			if atomic.LoadInt32(&self.mining) == 0 {
				self.currentMu.Lock()
				txs := make(map[common.Address]types.Transactions)
				for _, tx := range ev.Txs {
					acc, _ := types.Sender(self.current.signer, tx)
					txs[acc] = append(txs[acc], tx)
				}
				txset := types.NewTransactionsByPriceAndNonce(self.current.signer, txs)

				self.current.commitTransactions(self.mux, txset, self.chain, self.coinbase)
				self.currentMu.Unlock()
			} else {
				// If we're mining, but nothing is being processed, wake on new transactions
				if self.config.Clique != nil && self.config.Clique.Period == 0 {
					self.commitNewWork()
				}
			}

			// System stopped
		case <-self.txsSub.Err():
			return
		case <-self.chainHeadSub.Err():
			return
		case <-self.chainSideSub.Err():
			return
		case <-self.chainRpowSub.Err():
			return
		}
	}
}

func (self *worker) wait() {
	for {
		mustCommitNewWork := true
		for result := range self.recv {
			atomic.AddInt32(&self.atWork, -1)

			if result == nil {
				continue
			}
			block := result.Block
			work := result.Work

			// Update the block hash in all logs since it is now available and not when the
			// receipt/log of individual transactions were created.
			for _, r := range work.receipts {
				for _, l := range r.Logs {
					l.BlockHash = block.Hash()
				}
			}
			for _, log := range work.state.Logs() {
				log.BlockHash = block.Hash()
			}
			stat, err := self.chain.WriteBlockWithState(block, work.receipts, work.state)
			if err != nil {
				log.Error("Failed writing block to chain", "err", err)
				continue
			}
			// check if canon block and write transactions
			if stat == core.CanonStatTy {
				// implicit by posting ChainHeadEvent
				mustCommitNewWork = false
			}
			// Broadcast the block and announce chain insertion event
			self.mux.Post(core.NewMinedBlockEvent{Block: block})
			var (
				events []interface{}
				logs   = work.state.Logs()
			)
			events = append(events, core.ChainEvent{Block: block, Hash: block.Hash(), Logs: logs})
			if stat == core.CanonStatTy {
				events = append(events, core.ChainHeadEvent{Block: block})
			}
			self.chain.PostChainEvents(events, logs)

			// Insert the block into the set of pending ones to wait for confirmations
			self.unconfirmed.Insert(block.NumberU64(), block.Hash(), self.chain)

			if mustCommitNewWork {
				self.commitNewWork()
			}
		}
	}
}

// push sends a new work task to currently live miner agents.
func (self *worker) push(work *Work) {
	if atomic.LoadInt32(&self.mining) != 1 {
		return
	}
	for agent := range self.agents {
		atomic.AddInt32(&self.atWork, 1)
		if ch := agent.Work(); ch != nil {
			ch <- work
		}
	}
}

// makeCurrent creates a new environment for the current cycle.
func (self *worker) makeCurrent(parent *types.Block, header *types.Header) error {
	state, err := self.chain.StateAt(parent.Root())
	if err != nil {
		return err
	}
	work := &Work{
		config:    self.config,
		signer:    types.NewEIP155Signer(self.config.ChainId),
		state:     state,
		ancestors: set.New(),
		family:    set.New(),
		uncles:    set.New(),
		header:    header,
		createdAt: time.Now(),
	}

	// when 08 is processed ancestors contain 07 (quick block)
	for _, ancestor := range self.chain.GetBlocksFromHash(parent.Hash(), 7) {
		for _, uncle := range ancestor.Uncles() {
			work.family.Add(uncle.Hash())
		}
		work.family.Add(ancestor.Hash())
		work.ancestors.Add(ancestor.Hash())
	}

	// Keep track of transactions which return errors so they can be removed
	work.tcount = 0
	self.current = work
	return nil
}

func (self *worker) commitNewWork() {
	self.mu.Lock()
	defer self.mu.Unlock()
	self.uncleMu.Lock()
	defer self.uncleMu.Unlock()
	self.currentMu.Lock()
	defer self.currentMu.Unlock()

	tstart := time.Now()
	parent := self.chain.CurrentBlock()
	tstamp := tstart.Unix()

	// this will ensure we're not going off too far in the future
	checkMiningTooFar(tstamp)

	// this will ensure block interval is legal
	if !self.checkBlockInterval(parent, tstamp) {
		return
	}
	// prepare head for mining
	header, blockNumber := self.headPrepare(parent, tstamp)

	// Only set the coinbase if we are mining (avoid spurious block rewards)
	if atomic.LoadInt32(&self.mining) == 1 {
		totalMinerNum := minerlist.ReadMinerNum(self.current.state)

		// check whether coinbase is legal miner
		if !self.isMiner(totalMinerNum, blockNumber) {
			return
		}

		// collect pre block info and calculate whether the miner is correct for current block
		var preQr []byte
		if header.Number.Cmp(common.Big1) == 0 {
			preQr = common.GenesisMinerQrSignature
		} else {
			preQr = parent.MinerQrSignature()
		}
		preCoinbase := parent.Coinbase()
		tstampSub := header.Time.Int64() - parent.Time().Int64()
		n := big.NewInt(tstampSub / common.BlockSlot.Int64())

		//check whether coinbase is valid miner
		IsValidMiner, level, preMinerid := self.checkIsVaildMiner(preCoinbase, preQr, blockNumber, totalMinerNum, n)
		if !IsValidMiner {
			return
		}

		// calculate minerQrSignature for current block
		qr, err := minerlist.CalQrOrIdNext(preCoinbase.Bytes(), blockNumber, preQr)
		if err != nil {
			log.Error("Failed to CalQrOrIdNext", "err", err)
			return
		}

		// Look up the wallet containing the requested signer
		minerQrSignature := self.calMinerQrSignature(qr)
		if minerQrSignature != nil {
			header.MinerQrSignature = bytes.Join([][]byte{minerQrSignature, qr.Bytes()}, []byte(""))
		} else {
			return
		}
		fmt.Println("calMinerQrSignature")
		// calculate PrimaryMiner and  DifficultyLevel for current block
		if totalMinerNum.Int64() != 0 {
			header.PrimaryMiner = common.BytesToAddress(minerlist.ReadMinerAddress(self.current.state, preMinerid))
		} else {
			header.PrimaryMiner = self.coinbase
		}
		header.DifficultyLevel = big.NewInt(level)
		if header.Number.Cmp(common.Big1) == 0 {
			header.DifficultyLevel = big.NewInt(0)
		}
		header.Coinbase = self.coinbase

		if err := self.engine.Prepare(self.chain, header, self.current.state); err != nil {
			log.Error("Failed to prepare header for mining", "err", err)
			return
		}
	} else {
		if err := self.engine.Prepare(self.chain, header, nil); err != nil {
			log.Error("Failed to prepare header for mining", "err", err)
			return
		}
	}

	// Could potentially happen if starting to mine in an odd state.
	err := self.makeCurrent(parent, header)
	if err != nil {
		log.Error("Failed to create mining context", "err", err)
		return
	}

	// Create the current work task and check any fork transitions needed
	work := self.current
	committeeCnt := self.chain.GetCommitteeCount()
	var pending map[common.Address]types.Transactions
	if header.IsCheckPoint.Cmp(common.Big1) == 0 && atomic.LoadInt32(&self.mining) == 1 {
		pending, err = self.eth.TxPool().GetValidPbft(blockNumber.Uint64()-1, common.GetIndexForVote(time.Now().Unix(), parent.Time().Int64()))
		gen, targetHash, _ := canGenBlockInCheckPoint(pending, committeeCnt)
		if !gen {
		DONE2:
			for {
				select {
				case <-self.chainRpowCh:
				default:
					break DONE2
				}
			}
			time.Sleep(10 * time.Millisecond)
			self.chainRpowCh <- 1
			return
		} else {
			if parent.Hash() != targetHash {
				log.Info("Switch block chain", "current hash", parent.Hash().Hex(), "parent height", parent.NumberU64(), "target hash", targetHash.Hex())
				self.chain.SwitchBlockChain(targetHash)
				for {
					curBlock := self.chain.CurrentBlock()
					if curBlock.Hash() == targetHash {
						self.chain.ClearTargetBlock()
						log.Info("Switch block chain successfull, continue to mine...")
						return
					}
					if curBlock.NumberU64() >= blockNumber.Uint64() {
						self.chain.ClearTargetBlock()
						log.Info("Switch block chain successfull, go to next mining", "current hash", curBlock.Hash().Hex(), "current height", curBlock.NumberU64(), "target height", blockNumber.Uint64())
						return
					}
					time.Sleep(500 * time.Millisecond)
				}
			}
		}
	} else {
		pending, err = self.eth.TxPool().Pending()
	}

	if err != nil {
		log.Error("Failed to fetch pending transactions", "err", err)
		return
	}
	txs := types.NewTransactionsByPriceAndNonce(self.current.signer, pending)
	work.commitTransactions(self.mux, txs, self.chain, self.coinbase)

	// Create the new block to seal with the consensus engine
	if work.Block, err = self.engine.Finalize(self.chain, header, work.state, work.txs, nil, work.receipts); err != nil {
		log.Error("Failed to finalize block for sealing", "err", err)
		return
	}
	// We only care about logging if we're actually mining.
	if atomic.LoadInt32(&self.mining) == 1 {
		log.Info("Commit new mining work", "number", work.Block.Number(), "txs", work.tcount, "elapsed", common.PrettyDuration(time.Since(tstart)))
		self.unconfirmed.Shift(work.Block.NumberU64() - 1)
	}
	self.push(work)
}

func checkMiningTooFar(tstamp int64) {
	if now := time.Now().Unix(); tstamp > now+1 {
		wait := time.Duration(tstamp-now) * time.Second
		log.Info("Mining too far in the future", "wait", common.PrettyDuration(wait))
		time.Sleep(wait)
	}
}

func (self *worker) checkBlockInterval(parent *types.Block, tstamp int64) bool {
	if parent.Time().Cmp(new(big.Int).SetInt64(tstamp-int64(common.BlockInterval))) > 0 {
	DONE:
		for {
			select {
			case <-self.chainRpowCh:
			default:
				break DONE
			}
		}
		time.Sleep(10 * time.Millisecond)
		self.chainRpowCh <- 1
		return false
	}
	return true
}

func (self *worker) headPrepare(parent *types.Block, tstamp int64) (header *types.Header, blcokNumber *big.Int) {
	num := parent.Number()
	header = &types.Header{
		ParentHash: parent.Hash(),
		Number:     num.Add(num, common.Big1),
		//GasLimit:   core.CalcGasLimit(parent),
		GasLimit: 210000000,
		Extra:    self.extra,
		Time:     big.NewInt(tstamp),
	}
	blcokNumber = header.Number
	if header.Number.Int64() >= common.VoteSlotForGenesis && int64(new(big.Int).Mod(header.Number, common.VoteSlot).Cmp(common.Big0)) == 0 {
		header.IsCheckPoint = big.NewInt(1)
	} else {
		header.IsCheckPoint = big.NewInt(0)
	}
	return header, blcokNumber
}

func (self *worker) checkIsVaildMiner(preCoinbase common.Address, preQr []byte, blockNumber *big.Int, totalMinerNum *big.Int, n *big.Int) (bool, int64, int64) {
	IsValidMiner, level, preMinerid := minerlist.IsValidMiner(self.current.state, self.coinbase, preCoinbase, preQr, blockNumber, totalMinerNum, n)
	if !IsValidMiner {
	DONE1:
		for {
			select {
			case <-self.chainRpowCh:
			default:
				break DONE1
			}
		}
		time.Sleep(10 * time.Millisecond)
		self.chainRpowCh <- 1
		return IsValidMiner, level, preMinerid
	}
	return IsValidMiner, level, preMinerid
}

func (self *worker) calMinerQrSignature(qr common.Hash) []byte {
	account := accounts.Account{Address: self.coinbase}
	wallet, err := self.eth.AccountManager().Find(account)
	if err != nil {
		log.Error("To be a miner of usechain RPOW, need local account", "err", err)
		return nil
	}

	minerQrSignature, err := wallet.SignHash(account, qr.Bytes())
	if err != nil {
		log.Error("Failed to unlock the coinbase account", "err", err)
		return nil
	}
	return minerQrSignature
}

func (self *worker) isMiner(totalMinerNum *big.Int, blockNumber *big.Int) bool {
	isMiner, flag := minerlist.IsMiner(self.current.state, self.coinbase, totalMinerNum, blockNumber)
	if !isMiner {
		if flag == 1 {
			if minerlist.GetMisconducts(self.current.state, self.coinbase).Int64() < common.MisconductLimitsLevel3 {
				log.Error("Coinbase is being punished, Mining will commence after the penalty period")
			} else {
				log.Error("Coinbase has been permanently punished, Mining is forbidden")
			}
		} else {
			log.Error("Coinbase needs to register as a miner, Please try 'miner.stop();admin.sleepBlocks(1);use.minerRegister({from:use.coinbase});admin.sleepBlocks(1);miner.start()'")
		}
		return false
	}
	return true
}

func canGenBlockInCheckPoint(txs map[common.Address]types.Transactions, cnt int32) (bool, common.Hash, uint32) {
	if float64(len(txs)) < math.Ceil(float64(cnt)*2/3) {
		return false, common.Hash{}, 0
	}

	hashCount := make(map[common.Hash]uint32)
	for _, list := range txs {
		for i := 0; i < list.Len(); i++ {
			payload := list[i].Data()
			hash := common.BytesToHash(payload[:common.HashLength])
			if _, ok := hashCount[hash]; ok {
				hashCount[hash]++
			} else {
				hashCount[hash] = 1
			}
		}
	}

	var maxCount uint32 = 0
	var maxHash common.Hash
	for hash, count := range hashCount {
		if count <= maxCount {
			continue
		}
		maxCount = count
		maxHash = hash
	}

	if float64(maxCount) < math.Ceil(float64(cnt)*2/3) {
		return false, maxHash, maxCount
	}

	return true, maxHash, maxCount
}

func (self *worker) commitUncle(work *Work, uncle *types.Header) error {
	hash := uncle.Hash()
	if work.uncles.Has(hash) {
		return fmt.Errorf("uncle not unique")
	}
	if !work.ancestors.Has(uncle.ParentHash) {
		return fmt.Errorf("uncle's parent unknown (%x)", uncle.ParentHash[0:4])
	}
	if work.family.Has(hash) {
		return fmt.Errorf("uncle already in family (%x)", hash)
	}
	work.uncles.Add(uncle.Hash())
	return nil
}

func (env *Work) commitTransactions(mux *event.TypeMux, txs *types.TransactionsByPriceAndNonce, bc *core.BlockChain, coinbase common.Address) {
	gp := new(core.GasPool).AddGas(env.header.GasLimit)

	var coalescedLogs []*types.Log

	for {
		// If we don't have enough gas for any further transactions then we're done
		if gp.Gas() < params.TxGas {
			log.Trace("Not enough gas for further transactions", "gp", gp)
			break
		}
		// Retrieve the next transaction and abort if all done
		tx := txs.Peek()
		if tx == nil {
			break
		}
		// Error may be ignored here. The error has already been checked
		// during transaction acceptance is the transaction pool.
		//
		// We use the eip155 signer regardless of the current hf.
		from, _ := types.Sender(env.signer, tx)
		// Check whether the tx is replay protected. If we're not in the EIP155 hf
		// phase, start ignoring the sender until we do.
		//if tx.Protected() && !env.config.IsEIP155(env.header.Number) {
		//	log.Trace("Ignoring reply protected transaction", "hash", tx.Hash(), "eip155", env.config.EIP155Block)
		//
		//	txs.Pop()
		//	continue
		//}
		// Start executing the transaction
		env.state.Prepare(tx.Hash(), common.Hash{}, env.tcount)

		err, logs := env.commitTransaction(tx, bc, coinbase, gp)
		switch err {
		case core.ErrGasLimitReached:
			// Pop the current out-of-gas transaction without shifting in the next from the account
			log.Trace("Gas limit exceeded for current block", "sender", from)
			txs.Pop()

		case core.ErrNonceTooLow:
			// New head notification data race between the transaction pool and miner, shift
			log.Trace("Skipping transaction with low nonce", "sender", from, "nonce", tx.Nonce())
			txs.Shift()

		case core.ErrNonceTooHigh:
			// Reorg notification data race between the transaction pool and miner, skip account =
			log.Trace("Skipping account with hight nonce", "sender", from, "nonce", tx.Nonce())
			txs.Pop()

		case nil:
			// Everything ok, collect the logs and shift in the next transaction from the same account
			coalescedLogs = append(coalescedLogs, logs...)
			env.tcount++
			txs.Shift()

		default:
			// Strange error, discard the transaction and get the next in line (note, the
			// nonce-too-high clause will prevent us from executing in vain).
			log.Debug("Transaction failed, account skipped", "hash", tx.Hash(), "err", err)
			txs.Shift()
		}
	}

	if len(coalescedLogs) > 0 || env.tcount > 0 {
		// make a copy, the state caches the logs and these logs get "upgraded" from pending to mined
		// logs by filling in the block hash when the block was mined by the local miner. This can
		// cause a race condition if a log was "upgraded" before the PendingLogsEvent is processed.
		cpy := make([]*types.Log, len(coalescedLogs))
		for i, l := range coalescedLogs {
			cpy[i] = new(types.Log)
			*cpy[i] = *l
		}
		go func(logs []*types.Log, tcount int) {
			if len(logs) > 0 {
				mux.Post(core.PendingLogsEvent{Logs: logs})
			}
			if tcount > 0 {
				mux.Post(core.PendingStateEvent{})
			}
		}(cpy, env.tcount)
	}
}

func (env *Work) commitTransaction(tx *types.Transaction, bc *core.BlockChain, coinbase common.Address, gp *core.GasPool) (error, []*types.Log) {
	snap := env.state.Snapshot()

	receipt, _, err := core.ApplyTransaction(env.config, bc, &coinbase, gp, env.state, env.header, tx, &env.header.GasUsed, vm.Config{})
	if err != nil {
		env.state.RevertToSnapshot(snap)
		return err, nil
	}
	env.txs = append(env.txs, tx)
	env.receipts = append(env.receipts, receipt)

	return nil, receipt.Logs
}
