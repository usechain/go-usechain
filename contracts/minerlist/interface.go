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
	"encoding/binary"
	"math/big"
	"math/rand"
	"strconv"
	"strings"

	"github.com/usechain/go-usechain/common"
	"github.com/usechain/go-usechain/common/hexutil"
	"github.com/usechain/go-usechain/core/state"
	"github.com/usechain/go-usechain/crypto"
	"github.com/usechain/go-usechain/crypto/sha3"
)

const (
	MinerListContract  = "0xfffffffffffffffffffffffffffffffff0000002"
	GenesisQrSignature = "8287dbe2b47bcc884dce4b9ea1a0dc76"
	ignoreSlot         = int64(1)
	paramIndex         = "0x0000000000000000000000000000000000000000000000000000000000000000"
)

func ReadMinerNum(statedb *state.StateDB) *big.Int {
	// get data from the contract statedb
	res := statedb.GetState(common.HexToAddress(MinerListContract), common.HexToHash(paramIndex))
	return res.Big()
}

func IsMiner(statedb *state.StateDB, miner common.Address, totalMinerNum *big.Int) bool {
	//add for test solo mining
	if totalMinerNum.Cmp(common.Big0) == 0 {
		return true
	}

	hash := sha3.NewKeccak256()
	hash.Write(hexutil.MustDecode(paramIndex))
	var keyIndex []byte
	keyIndex = hash.Sum(keyIndex)

	for i := int64(0); i < totalMinerNum.Int64(); i++ {
		if checkAddress(statedb, miner, keyIndex, i) {
			return !isPunishMiner(statedb, miner, totalMinerNum)
		}
	}
	return false
}

func CalQr(base []byte, number *big.Int, preQrSignature []byte) common.Hash {
	return crypto.Keccak256Hash(bytes.Join([][]byte{base, number.Bytes(), preQrSignature}, []byte("")))
}

func IsValidMiner(state *state.StateDB, miner common.Address, preCoinbase common.Address, preSignatureQr []byte, blockNumber *big.Int, totalMinerNum *big.Int, offset *big.Int, preDifficultyLevel *big.Int) (bool, int64) {
	hash := sha3.NewKeccak256()
	hash.Write(hexutil.MustDecode(paramIndex))
	var keyIndex []byte
	keyIndex = hash.Sum(keyIndex)

	// add for test solo mining
	if totalMinerNum.Cmp(common.Big0) == 0 {
		return true, 0
	}
	if totalMinerNum.Cmp(common.Big1) == 0 {
		return checkAddress(state, miner, keyIndex, 0), 0
	}

	minerlist := genRandomMinerList(preSignatureQr, offset, totalMinerNum)
	preLevel, _ := strconv.ParseFloat(preDifficultyLevel.String(), 64)
	totalminernum, _ := strconv.ParseFloat(totalMinerNum.String(), 64)
	idTarget := CalIdTarget(preCoinbase, preSignatureQr, blockNumber, totalMinerNum, state)
	var oldNode []int64
	oldNode = append(oldNode, idTarget.Int64())
	var level float64
	if preLevel > 3 {
		level = 0.3
	} else {
		level = 0.1 * preLevel
	}

	if offset.Int64() == 0 {
		idTargetfloat, _ := strconv.ParseFloat(idTarget.String(), 64)
		if preDifficultyLevel.Int64() != 0 && idTargetfloat > (float64(0.618)-level)*totalminernum {
			return false, 0
		}
		return checkAddress(state, miner, keyIndex, minerlist[idTarget.Int64()]), 0
	} else {
		id := calId(idTarget, preSignatureQr, totalMinerNum, offset, state, keyIndex)
		idfloat, _ := strconv.ParseFloat(id.String(), 64)
		if preDifficultyLevel.Int64() != 0 && idfloat > (float64(0.618)-level)*totalminernum {
			return false, offset.Int64()
		}

		return checkAddress(state, miner, keyIndex, minerlist[id.Int64()]), offset.Int64()
	}
}

func CalIdTarget(preCoinbase common.Address, preSignatureQr []byte, blockNumber *big.Int, totalMinerNum *big.Int, state *state.StateDB) *big.Int {
	hash := sha3.NewKeccak256()
	hash.Write(hexutil.MustDecode(paramIndex))
	var keyIndex []byte
	keyIndex = hash.Sum(keyIndex)
	qr := CalQr(preCoinbase.Bytes(), blockNumber, preSignatureQr)
	idTarget := new(big.Int).Mod(qr.Big(), totalMinerNum)
	idTarget = checkIdTargetOrId(state, keyIndex, idTarget, totalMinerNum)
	return idTarget
}

func ReadMinerAddress(statedb *state.StateDB, offset int64) []byte {
	// get data from the contract statedb
	hash := sha3.NewKeccak256()
	hash.Write(hexutil.MustDecode(paramIndex))
	var keyIndex []byte
	keyIndex = hash.Sum(keyIndex)

	res := statedb.GetState(common.HexToAddress(MinerListContract), common.HexToHash(common.IncreaseHexByNum(keyIndex, offset)))
	return res.Bytes()
}

//Generate a random list of miners for each block slot
func genRandomMinerList(preSignatureQr []byte, offset *big.Int, totalMinerNum *big.Int) []int64 {
	s1 := rand.NewSource(int64(binary.BigEndian.Uint64(preSignatureQr)) + offset.Int64())
	r1 := rand.New(s1)
	list := make([]int64, totalMinerNum.Int64())
	for i := int64(0); i < totalMinerNum.Int64(); i++ {
		list[i] = i
	}
	for i := int64(0); i < totalMinerNum.Int64(); i++ {
		r := r1.Int63n(totalMinerNum.Int64() - i)
		temp := list[r]
		list[r] = list[i]
		list[i] = temp
	}
	return list
}

func calId(idTarget *big.Int, preSignatureQr []byte, totalMinerNum *big.Int, offset *big.Int, state *state.StateDB, keyIndex []byte) *big.Int {
	idNext := CalQr(idTarget.Bytes(), offset, preSignatureQr)
	id := new(big.Int).Mod(idNext.Big(), totalMinerNum)
	id = checkIdTargetOrId(state, keyIndex, id, totalMinerNum)

	var oldNode []int64
	for i := ignoreSlot; i > 0; i-- {
		idNextTemp := CalQr(idTarget.Bytes(), new(big.Int).Sub(offset, big.NewInt(i)), preSignatureQr)
		idTemp := new(big.Int).Mod(idNextTemp.Big(), totalMinerNum)
		idTemp = checkIdTargetOrId(state, keyIndex, id, totalMinerNum)
		oldNode = append(oldNode, idTemp.Int64())
	}

DONE:
	for {
		for index, value := range oldNode {
			if id.Int64() == value {
				id.Add(id, common.Big1)
				id.Mod(id, totalMinerNum)
				id = checkIdTargetOrId(state, keyIndex, id, totalMinerNum)
				break
			}
			if int64(cap(oldNode)) == int64(index+1) {
				break DONE
			}
		}
	}

	return id
}

func checkAddress(statedb *state.StateDB, miner common.Address, keyIndex []byte, offset int64) bool {
	res := statedb.GetState(common.HexToAddress(MinerListContract), common.HexToHash(common.IncreaseHexByNum(keyIndex, offset)))
	if strings.EqualFold(res.String()[26:], miner.String()[2:]) {
		return true
	}
	return false
}

func checkIdTargetOrId(statedb *state.StateDB, keyIndex []byte, idTarget *big.Int, totalMinerNum *big.Int) *big.Int {
	var res common.Hash
	for {
		res = statedb.GetState(common.HexToAddress(MinerListContract), common.HexToHash(common.IncreaseHexByNum(keyIndex, idTarget.Int64())))
		if isPunishMiner(statedb, common.StringToAddress("0x"+res.String()[26:]), totalMinerNum) {
			idTarget.Add(idTarget, common.Big1)
			idTarget.Mod(idTarget, totalMinerNum)
		} else {
			return idTarget
		}
	}
}

func isPunishMiner(statedb *state.StateDB, miner common.Address, totalMinerNum *big.Int) bool {
	if totalMinerNum.Cmp(common.Big1) < 1 {
		return false
	}

	web3key := paramIndex + miner.String()[2:]
	hash := sha3.NewKeccak256()
	hash.Write(hexutil.MustDecode(web3key))
	var keyIndex []byte
	keyIndex = hash.Sum(keyIndex)

	res := statedb.GetState(common.HexToAddress(MinerListContract), common.HexToHash(string(keyIndex)))

	if res.Big().Cmp(common.PunishMinerThreshold) >= 0 {
		return true
	}
	return false
}
