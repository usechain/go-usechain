// Copyright 2018 The go-usechain Authors
// This file is part of the go-usechain library.
//
// The go-usechain library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-usechain library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-usechain library. If not, see <http://www.gnu.org/licenses/>.

package vote

import (
	"math/big"
	"sync/atomic"
	"sync"
	"time"
	"github.com/usechain/go-usechain/accounts"
	"github.com/usechain/go-usechain/core"
	"github.com/usechain/go-usechain/core/types"
	"github.com/usechain/go-usechain/common"
	"github.com/usechain/go-usechain/contracts/manager"
	"github.com/usechain/go-usechain/event"
	"github.com/usechain/go-usechain/log"
)

var (
	// chainHeadChanSize is the size of channel listening to ChainHeadEvent.
	chainHeadChanSize = 10
)

// Backend wraps all methods required for voting.
type Backend interface {
	AccountManager() *accounts.Manager
	BlockChain() *core.BlockChain
	TxPool() *core.TxPool
	ChainID() *big.Int
}

//The struct of voter
type Voter struct {
	chainHeadCh  chan core.ChainHeadEvent
	chainHeadSub event.Subscription

	chainID 	 *big.Int
	blockchain   *core.BlockChain
	txpool		 *core.TxPool
	manager		 *accounts.Manager
	t            *time.Timer

	mu sync.Mutex

	voting   	 int32
	votebase	 common.Address
}

// NewVoter creates a new voter
func NewVoter(eth Backend, coinbase common.Address) *Voter{
	voter := &Voter{
		chainHeadCh: 	make(chan core.ChainHeadEvent, chainHeadChanSize),
		chainID:		eth.ChainID(),
		blockchain:		eth.BlockChain(),
		votebase:		coinbase,
		txpool:			eth.TxPool(),
		manager:		eth.AccountManager(),
	}
	// Subscribe events for blockchain
	voter.chainHeadSub = eth.BlockChain().SubscribeChainHeadEvent(voter.chainHeadCh)
	voter.t = time.NewTimer(time.Hour * 24)

	go voter.VoteLoop()
	return voter
}

//Start voting
func (self *Voter) Start(coinbase common.Address) {
	self.SetVotebase(coinbase)
	atomic.StoreInt32(&self.voting, 1)

	header := self.blockchain.CurrentHeader()
	mod := big.NewInt(0).Mod(header.Number, common.VoteSlot).Int64()
	if mod == common.VoteSlot.Int64() - 1 {
		self.voteChain()
		self.t.Reset(time.Second * 60)
	}
	log.Info("Starting voting operation")
}

//Stop voting
func (self *Voter) Stop() {
	atomic.StoreInt32(&self.voting, 0)
}

//Check the voting state
func (self *Voter) Voting() bool {
	return atomic.LoadInt32(&self.voting) > 0
}

//Voting loop
func (self *Voter) VoteLoop() {
	for  {
		select {
		//get new block head event
		case <-self.chainHeadCh:
			self.vote()
		//expire & re-send
		case <-self.t.C:
			self.vote()
		}
	}
}

//Set the address for voting
func (self *Voter) SetVotebase(addr common.Address) {
	self.mu.Lock()
	defer self.mu.Unlock()
	self.votebase = addr
}

//get the votebase
func (self *Voter) Votebase() common.Address {
	return self.votebase
}

//vote
func (self *Voter) vote() {
	if self.Voting() {
		header := self.blockchain.CurrentHeader()
		mod := big.NewInt(0).Mod(header.Number, common.VoteSlot).Int64()
		log.Trace("Voting CurrentHeader", "height", header.Number)

		//meet the checkpoint, vote
		if mod == common.VoteSlot.Int64() - 1 {
			self.voteChain()
			self.t.Reset(time.Second * 60)
		} else if mod == common.VoteSlot.Int64() {
			self.t.Stop()
		}
	}
	return
}

//Sign the vote, and broadcast it
func (self *Voter) voteChain() {
	//get the account
	account := accounts.Account{Address: self.votebase}
	wallet, err := self.manager.Find(account)
	if err != nil {
		log.Error("To be a committee of usechain, need local account","err", err)
		return
	}

	//check the votebase whether a committee
	//get the nonce from current header to ensure the tx be packed in the next block
	if !manager.IsCommittee(self.txpool.StateDB(),self.votebase) {
		log.Error("Not a committee, can't vote")
		return
	}

	//new a transaction
	nonce := self.txpool.StateDB().GetNonce(self.votebase)
	tx := types.NewPbftMessage(nonce, self.writeVoteInfo())
	signedTx, err := wallet.SignTx(account, tx, nil)
	if err != nil {
		log.Error("Sign the committee Msg failed, Please unlock the verifier account", "err", err)
		return
	}

	log.Info("Checkpoint vote is sent", "hash", signedTx.Hash().String())
	//add tx to the txpool
	self.txpool.AddLocal(signedTx)
}

//Fill the vote info
func (self *Voter) writeVoteInfo() []byte{
	header := self.blockchain.CurrentHeader()
	return append(header.Hash().Bytes(), header.Number.Bytes()...)
}