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

package state

import (
	"encoding/json"
	"fmt"

	"github.com/usechain/go-usechain/common"
	"github.com/usechain/go-usechain/rlp"
	"github.com/usechain/go-usechain/trie"
)

type DumpAccount struct {
	Balance  string            `json:"balance"`
	USGBalance string		   `json:"USGbalance"`
	Nonce    uint64            `json:"nonce"`
	Root     string            `json:"root"`
	CodeHash string            `json:"codeHash"`
	Code     string            `json:"code"`
	Storage  map[string]string `json:"storage"`

	TimePoint	   string	   `json:"timepoint"`
	TradePoints    uint64      `json:"tradepoints"`
	Certifications uint64      `json:"certifications"`
	CertPoints     uint64      `json:"certpoints"`
	ReviewPoints   string      `json:"reviewpoints"`
	RewardPoints   string      `json:"rewardpoints"`
	Lock           common.Lock `json:"lock"`
}

type Dump struct {
	Root     string                 `json:"root"`
	Accounts map[string]DumpAccount `json:"accounts"`
}

func (self *StateDB) RawDump() Dump {
	dump := Dump{
		Root:     fmt.Sprintf("%x", self.trie.Hash()),
		Accounts: make(map[string]DumpAccount),
	}

	it := trie.NewIterator(self.trie.NodeIterator(nil))
	for it.Next() {
		addr := self.trie.GetKey(it.Key)
		var data Account
		if err := rlp.DecodeBytes(it.Value, &data); err != nil {
			panic(err)
		}

		obj := newObject(nil, common.BytesToAddress(addr), data, nil)
		account := DumpAccount{
			Balance:  data.Balance.String(),
			USGBalance: data.USGBalance.String(),
			Nonce:    data.Nonce,
			Root:     common.Bytes2Hex(data.Root[:]),
			CodeHash: common.Bytes2Hex(data.CodeHash),
			Code:     common.Bytes2Hex(obj.Code(self.db)),
			Storage:  make(map[string]string),

			TimePoint:		data.TimePoint.String(),
			TradePoints:    data.TradePoints,
			Certifications: data.Certifications,
			CertPoints:     data.CertPoints,
			ReviewPoints:   data.ReviewPoints.String(),
			RewardPoints:   data.RewardPoints.String(),
			Lock:           *data.Lock,
		}
		storageIt := trie.NewIterator(obj.getTrie(self.db).NodeIterator(nil))
		for storageIt.Next() {
			account.Storage[common.Bytes2Hex(self.trie.GetKey(storageIt.Key))] = common.Bytes2Hex(storageIt.Value)
		}
		dump.Accounts[common.Bytes2Hex(addr)] = account
	}
	return dump
}

func (self *StateDB) Dump() []byte {
	json, err := json.MarshalIndent(self.RawDump(), "", "    ")
	if err != nil {
		fmt.Println("dump err", err)
	}

	return json
}
