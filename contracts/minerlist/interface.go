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
	"math/big"
	"strings"

	"github.com/usechain/go-usechain/common"
	"github.com/usechain/go-usechain/common/hexutil"
	"github.com/usechain/go-usechain/core/state"
	"github.com/usechain/go-usechain/crypto"
	"github.com/usechain/go-usechain/crypto/sha3"
)

const (
	MinerListContract = "0xfffffffffffffffffffffffffffffffff0000002"
	ignoreSlot        = int64(1)
	paramIndexFull    = "0x0000000000000000000000000000000000000000000000000000000000000000"
	paramIndexaHead   = "000000000000000000000000"
)

var keyIndex = calKeyIndex()

// Return the number of miner
func ReadMinerNum(statedb *state.StateDB) *big.Int {
	// get data from the contract statedb
	res := statedb.GetState(common.HexToAddress(MinerListContract), common.HexToHash(paramIndexFull))
	return res.Big()
}

// Return whether the miner is legal or not
// "legal" means the right to participate in mining
func IsMiner(statedb *state.StateDB, miner common.Address, totalMinerNum *big.Int) bool {
	//add for solo mining
	if totalMinerNum.Cmp(common.Big0) == 0 {
		return true
	}

	for i := int64(0); i < totalMinerNum.Int64(); i++ {
		if checkAddress(statedb, miner, i) {
			return !isPunishMiner(statedb, miner, totalMinerNum)
		}
	}
	return false
}

// Return whether the miner is valid or not , difficultlevel and preMinerid
func IsValidMiner(state *state.StateDB, miner common.Address, preCoinbase common.Address, preSignatureQr []byte, blockNumber *big.Int, totalMinerNum *big.Int, offset *big.Int) (bool, int64, int64) {
	//TODO: add time penalty mechanism
	// add for test solo mining
	if totalMinerNum.Cmp(common.Big0) == 0 {
		return true, 0, 0
	}
	if totalMinerNum.Cmp(common.Big1) == 0 {
		return checkAddress(state, miner, 0), 0, 0
	}

	// calculate the miner  who should be the first out of blocks
	idTarget := CalIdTarget(preCoinbase, preSignatureQr, blockNumber, totalMinerNum, state)

	if offset.Int64() == 0 {
		return checkAddress(state, miner, idTarget.Int64()), offset.Int64(), idTarget.Int64()
	} else {
		id := calId(idTarget, preSignatureQr, totalMinerNum, offset, state)
		return checkAddress(state, miner, id.Int64()), offset.Int64(), idTarget.Int64()
	}
}

func CalIdTarget(preCoinbase common.Address, preSignatureQr []byte, blockNumber *big.Int, totalMinerNum *big.Int, state *state.StateDB) *big.Int {
	// Qr = Hash(coinbase_(r-1) || r-1 || Sig_(r-1))
	qr := CalQrOrIdNext(preCoinbase.Bytes(), blockNumber, preSignatureQr)
	idTarget := new(big.Int).Mod(qr.Big(), totalMinerNum)
	// check whether the id is be punished
	idTarget = checkIdTargetOrId(state, idTarget, totalMinerNum)
	return idTarget
}

func ReadMinerAddress(statedb *state.StateDB, offset int64) []byte {
	// get data from the contract statedb
	res := statedb.GetState(common.HexToAddress(MinerListContract), common.HexToHash(common.IncreaseHexByNum(keyIndex, offset)))
	return res.Bytes()
}

func calId(idTarget *big.Int, preSignatureQr []byte, totalMinerNum *big.Int, offset *big.Int, state *state.StateDB) *big.Int {
	// qrOffset = hash(ID_Target_r || nλ || Sig_(r-1))
	qrOffset := CalQrOrIdNext(idTarget.Bytes(), offset, preSignatureQr)
	id := new(big.Int).Mod(qrOffset.Big(), totalMinerNum)
	id = checkIdTargetOrId(state, id, totalMinerNum)

	//id can't be the same as ignoreSlot before
	var oldNode []int64
	for i := ignoreSlot; i > 0; i-- {
		idNextTemp := CalQrOrIdNext(idTarget.Bytes(), new(big.Int).Sub(offset, big.NewInt(i)), preSignatureQr)
		idTemp := new(big.Int).Mod(idNextTemp.Big(), totalMinerNum)
		idTemp = checkIdTargetOrId(state, id, totalMinerNum)
		oldNode = append(oldNode, idTemp.Int64())
	}
DONE:
	for {
		for index, value := range oldNode {
			if id.Int64() == value {
				id.Add(id, common.Big1)
				id.Mod(id, totalMinerNum)
				id = checkIdTargetOrId(state, id, totalMinerNum)
				break
			}
			if int64(cap(oldNode)) == int64(index+1) {
				break DONE
			}
		}
	}

	return id
}

func CalQrOrIdNext(base []byte, number *big.Int, preQrSignature []byte) common.Hash {
	return crypto.Keccak256Hash(bytes.Join([][]byte{base, number.Bytes(), preQrSignature}, []byte("")))
}

// Compare the address to the minerlist contract by offset
func checkAddress(statedb *state.StateDB, miner common.Address, offset int64) bool {
	res := statedb.GetState(common.HexToAddress(MinerListContract), common.HexToHash(common.IncreaseHexByNum(keyIndex, offset)))
	if strings.EqualFold(res.String()[26:], miner.String()[2:]) {
		return true
	}
	return false
}

// Check whether the miner is be punished by idOriginal , and return a right id
func checkIdTargetOrId(statedb *state.StateDB, idOriginal *big.Int, totalMinerNum *big.Int) *big.Int {
	var res common.Hash
	for {
		res = statedb.GetState(common.HexToAddress(MinerListContract), common.HexToHash(common.IncreaseHexByNum(keyIndex, idOriginal.Int64())))
		if isPunishMiner(statedb, common.StringToAddress("0x"+res.String()[26:]), totalMinerNum) {
			idOriginal.Add(idOriginal, common.Big1)
			idOriginal.Mod(idOriginal, totalMinerNum)
		} else {
			return idOriginal
		}
	}
}

// Return whether the miner is be punished
func isPunishMiner(statedb *state.StateDB, miner common.Address, totalMinerNum *big.Int) bool {
	if totalMinerNum.Cmp(common.Big1) < 1 {
		return false
	}

	web3key := paramIndexaHead + miner.Hex()[2:] + common.BigToHash(big.NewInt(2)).Hex()[2:]
	hash := sha3.NewKeccak256()
	var keyIndex []byte
	b, _ := hex.DecodeString(web3key)
	hash.Write(b)
	keyIndex = hash.Sum(keyIndex)

	// get data from the contract statedb
	res := statedb.GetState(common.HexToAddress(MinerListContract), common.BytesToHash(keyIndex))

	if res.Big().Cmp(common.MisconductLimits) >= 0 {
		return true
	}
	return false
}

func calKeyIndex() []byte {
	hash := sha3.NewKeccak256()
	hash.Write(hexutil.MustDecode(paramIndexFull))
	var keyIndex []byte
	keyIndex = hash.Sum(keyIndex)
	return keyIndex
}
