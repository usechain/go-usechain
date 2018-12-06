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
	"github.com/usechain/go-usechain/log"
)

var (
	active 	= true

	big0 	= big.NewInt(0)
	big20 	= big.NewInt(20)

	// chainHeadChanSize is the size of channel listening to ChainHeadEvent.
	chainHeadChanSize = 10
)

//The struct of voter
type voter struct {
	chainHeadCh  chan core.ChainHeadEvent
	blockchain   *core.BlockChain
	txpool		 *core.TxPool
	manager		 *accounts.Manager

	votebase	 common.Address
}

// NewVoter creates a new voter
func NewVoter(bc *core.BlockChain, txpool *core.TxPool, manager *accounts.Manager, coinbase common.Address) *voter{
	voter := &voter{
		chainHeadCh: 	make(chan core.ChainHeadEvent, chainHeadChanSize),
		blockchain:		bc,
		votebase:		coinbase,
		txpool:			txpool,
		manager:		manager,
	}
	return voter
}

//Voting loop
func (self *voter) VoteLoop() {
	for active {
		header := self.blockchain.CurrentHeader()

		if big.NewInt(0).Mod(header.Number, big20) == big0 {
			self.voteChain()
		}
	}
}

//Sign the vote, and broadcast it
func (self *voter) voteChain() {
	//check the votebase
	///TODO: check the vote whether a committee, read from contract

	//get the account
	account := accounts.Account{Address: self.votebase}
	wallet, err := self.manager.Find(account)
	if err != nil {
		log.Error("To be a committee of usechain, need local account","err", err)
		return
	}

	//new a transaction
	nonce := self.txpool.State().GetNonce(self.votebase)
	tx := types.NewPbftMessage(nonce, self.writeVoteInfo())
	signedTx, err := wallet.SignTx(account, tx, nil)
	if err != nil {
		log.Error("Sign the committee Msg failed, Please unlock the verifier account", "err", err)
	}

	//add tx to the txpool
	self.txpool.AddLocal(signedTx)
}

//Fill the vote info
func (self *voter) writeVoteInfo() []byte{
	header := self.blockchain.CurrentHeader()
	return append(header.Hash().Bytes(), header.Number.Bytes()...)
}