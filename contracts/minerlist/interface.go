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

package minerlist

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"github.com/usechain/go-usechain/common"
	"github.com/usechain/go-usechain/core/state"
	"github.com/usechain/go-usechain/crypto/sha3"
)

const (
	MinerListContract = "0xfffffffffffffffffffffffffffffffff0000002"
)

func decodeHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func formatData64bytes(_data string) string{
	dataRawlength := len(_data)

	if dataRawlength > 64 {
		fmt.Println("the string is explicit the length")
		return _data;
	}
	for index := 0; index < 64 - dataRawlength; index++ {
		_data = "0" + _data;
	}
	return _data
}

func ReadMinerNum(statedb *state.StateDB) *big.Int {
	paramIndex := "0000000000000000000000000000000000000000000000000000000000000000"

	// get data from the contract statedb
	res := statedb.GetState(common.HexToAddress(MinerListContract), common.HexToHash(paramIndex))
	return res.Big()
}


func IsMiner(statedb *state.StateDB, miner common.Address) bool {
	key := formatData64bytes(miner.Hex()[2:])
	paramIndex := "0000000000000000000000000000000000000000000000000000000000000001"

	web3key := key + paramIndex

	hash := sha3.NewKeccak256()
	var keyIndex []byte
	hash.Write(decodeHex(web3key))
	keyIndex = hash.Sum(keyIndex)

	// get data from the contract statedb
	res := statedb.GetState(common.HexToAddress(MinerListContract), common.HexToHash(hex.EncodeToString(keyIndex)))

	return res.Big().Cmp(big.NewInt(1)) == 0
}
