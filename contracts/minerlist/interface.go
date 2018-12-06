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
	"bytes"
	"encoding/hex"
	"github.com/usechain/go-usechain/log"
	"github.com/usechain/go-usechain/common"
	"github.com/usechain/go-usechain/core/state"
	"github.com/usechain/go-usechain/crypto"
	"github.com/usechain/go-usechain/crypto/sha3"
	"math/big"
	"strings"
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

func ReadMinerNum(statedb *state.StateDB) *big.Int {
	paramIndex := "0000000000000000000000000000000000000000000000000000000000000000"
	// get data from the contract statedb
	res := statedb.GetState(common.HexToAddress(MinerListContract), common.HexToHash(paramIndex))
	return res.Big()
}

// return the string data that has been added to the num
func IncreaseHexByNum(indexKeyHash []byte, num int64) string {
	x := new(big.Int).SetBytes(indexKeyHash)
	y := big.NewInt(int64(num))
	x.Add(x, y)
	return hex.EncodeToString(x.Bytes())
}

func IsMiner(statedb *state.StateDB, miner common.Address) bool {
	paramIndex := "0000000000000000000000000000000000000000000000000000000000000000"
	hash := sha3.NewKeccak256()
	hash.Write(decodeHex(paramIndex))
	var keyIndex []byte
	keyIndex = hash.Sum(keyIndex)
	for i := int64(0); i < ReadMinerNum(statedb).Int64() ; i++ {
		res := statedb.GetState(common.HexToAddress(MinerListContract), common.HexToHash(IncreaseHexByNum(keyIndex,i)))
		if strings.EqualFold(res.String()[26:], miner.String()[2:]) {
			return true
		}
	}
	return false
}

/*func IsValidMiner(state *state.StateDB, miner common.Address, index *big.Int, difficultyLevel *big.Int) bool {
	totalNum, _ := strconv.ParseFloat(ReadMinerNum(state).String(), 64)
	level, _ := strconv.ParseFloat(difficultyLevel.String(),64)
	id, _ := strconv.ParseFloat(index.String(), 64)

	if id >= totalNum / level && totalNum > 1{
		return false
	}

	paramIndex := "0000000000000000000000000000000000000000000000000000000000000000"
	hash := sha3.NewKeccak256()
	hash.Write(decodeHex(paramIndex))
	var keyIndex []byte
	keyIndex = hash.Sum(keyIndex)
	// get data from the contract statedb
	res := state.GetState(common.HexToAddress(MinerListContract), common.HexToHash(IncreaseHexByNum(keyIndex,n.Int64())))
	if strings.EqualFold(res.String()[26:], miner.String()[2:]){
		return true
	}
	return false
}*/

func CalQr(base []byte, number *big.Int, preQrSignature []byte) (common.Hash) {
	return crypto.Keccak256Hash(bytes.Join([][]byte{base, number.Bytes(), preQrSignature}, []byte("")))
}

func IsValidMiner(state *state.StateDB, miner common.Address, preCoinbase common.Address, preSignatureQr []byte, blockNumber *big.Int, totalMinerNum *big.Int, n *big.Int) (bool) {
	//preLevel, _ :=strconv.ParseFloat(difficultyLevel.String(),64)
	qr := CalQr(preCoinbase.Bytes(), blockNumber, preSignatureQr)
	idTarget := new(big.Int).Rem(qr.Big(), totalMinerNum)
	paramIndex := "0000000000000000000000000000000000000000000000000000000000000000"
	hash := sha3.NewKeccak256()
	hash.Write(decodeHex(paramIndex))
	var keyIndex []byte
	keyIndex = hash.Sum(keyIndex)
	for i := int64(0); i <= n.Int64(); i++ {
		if (i == 0) {
			res := state.GetState(common.HexToAddress(MinerListContract), common.HexToHash(IncreaseHexByNum(keyIndex, idTarget.Int64())))
			if strings.EqualFold(res.String()[26:], miner.String()[2:]) {
				log.Debug("i==0 id: ", "idtarget", idTarget)
				return true
			}
		} else {
			idn := CalQr(idTarget.Bytes(), big.NewInt(i), preSignatureQr)
			id := new(big.Int).Rem(idn.Big(), totalMinerNum)
			res := state.GetState(common.HexToAddress(MinerListContract), common.HexToHash(IncreaseHexByNum(keyIndex, id.Int64())))
			if strings.EqualFold(res.String()[26:], miner.String()[2:]) {
				log.Debug(" id: ", "id", id)
				return true
			}
		}
	}
	return false
}