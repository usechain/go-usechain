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

	"github.com/usechain/go-usechain/accounts"
	"github.com/usechain/go-usechain/core"
	"github.com/usechain/go-usechain/core/types"
	"github.com/usechain/go-usechain/common"
	"github.com/usechain/go-usechain/contracts/manager"
	"github.com/usechain/go-usechain/event"
	"github.com/usechain/go-usechain/log"
	"sync/atomic"
	"sync"
	"fmt"
)

var (
	big0 	= big.NewInt(0)
	big9	= big.NewInt(9)
	big10 	= big.NewInt(10)


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
	return voter
}

//Start voting
func (self *Voter) Start(coinbase common.Address) {
	self.SetVotebase(coinbase)
	atomic.StoreInt32(&self.voting, 1)

	log.Info("Starting voting operation")
	go self.VoteLoop()
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
	header := self.blockchain.CurrentHeader()
	if big.NewInt(0).Mod(header.Number, big10) == big9 {
		self.voteChain()
	}

	for self.Voting() {
		select {
			case <-self.chainHeadCh:
				header := self.blockchain.CurrentHeader()
				log.Debug("CurrentHeader", "height", header.Number)

				//if big.NewInt(0).Mod(header.Number, big10).Int64() == big10.Int64() - 1 {
					self.voteChain()
				//}
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
	nonce := self.txpool.State().GetNonce(self.votebase)
	managerContract, err := manager.NewManagerContract(self.blockchain)
	if err != nil {
		log.Error("manager contract re-construct failed")
		return
	}
	res, _ := managerContract.CallContract(self.votebase, nonce, "MAX_COMMITTEEMAN_COUNT")
	fmt.Printf("The manager contract call %x \n", res)

	//new a transaction
	tx := types.NewPbftMessage(nonce, self.writeVoteInfo())
	signedTx, err := wallet.SignTx(account, tx, nil)
	if err != nil {
		log.Error("Sign the committee Msg failed, Please unlock the verifier account", "err", err)
	}

	log.Info("Checkpoint vote is sent", "hash", tx.Hash().String())
	//add tx to the txpool
	self.txpool.AddLocal(signedTx)
}

//Fill the vote info
func (self *Voter) writeVoteInfo() []byte{
	header := self.blockchain.CurrentHeader()
	return append(header.Hash().Bytes(), header.Number.Bytes()...)
}