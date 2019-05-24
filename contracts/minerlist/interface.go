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
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"github.com/usechain/go-usechain/common"
	"github.com/usechain/go-usechain/common/hexutil"
	"github.com/usechain/go-usechain/core/state"
	"github.com/usechain/go-usechain/crypto"
	"github.com/usechain/go-usechain/crypto/sha3"
	"math/big"
	"math/rand"
	"strings"
)

const (
	MinerListContract = "UmixYUgBHA9vJj47myQKn8uZAm4anEfrG78"
	ignoreSlot        = int64(1)
	paramIndexFull    = "0x0000000000000000000000000000000000000000000000000000000000000000"
	paramIndexaHead   = "000000000000000000000000"
	PreQrLength       = 97
)

var keyIndex = calKeyIndex()

// Return the number of miner
func ReadMinerNum(statedb *state.StateDB) *big.Int {
	// get data from the contract statedb
	res := statedb.GetState(common.Base58AddressToAddress(common.StringToBase58Address(MinerListContract)), common.HexToHash(paramIndexFull))
	return res.Big()
}

// Return whether the miner is legal or not
// "legal" means the right to participate in mining
// Not whether the miners are online but whether the miners are being punished
// 0 means miners, 1 means punished, 2 means not on the miners' list
func IsMiner(statedb *state.StateDB, miner common.Address, totalMinerNum *big.Int, blockNumber *big.Int) (bool, int) {
	//add for solo mining
	if totalMinerNum.Cmp(common.Big0) == 0 {
		return true, 0
	}

	for i := int64(0); i < totalMinerNum.Int64(); i++ {
		if checkAddress(statedb, miner, i) {
			if !isPunishMiner(statedb, miner, totalMinerNum, blockNumber) {
				return true, 0
			} else {
				return false, 1
			}
		}
	}
	return false, 2
}

// Return whether the miner is legal or not
// "legal" means the right to participate in mining
func IsPunishedMiner(statedb *state.StateDB, miner common.Address, totalMinerNum *big.Int, blockNumber *big.Int) bool {
	//add for solo mining
	if totalMinerNum.Cmp(common.Big0) == 0 {
		return true
	}

	for i := int64(0); i < totalMinerNum.Int64(); i++ {
		if checkAddress(statedb, miner, i) {
			return isPunishMiner(statedb, miner, totalMinerNum, blockNumber)
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

	// if there is only one valid miner
	isOnlyOneMinerValid, index := isOnlyOneMinerValid(state, totalMinerNum, blockNumber)
	if isOnlyOneMinerValid && isOnLine(state, miner) {
		return checkAddress(state, miner, index), 0, 0
	}

	// calculate the miner  who should be the first out of blocks
	idTarget := CalIdTarget(preCoinbase, preSignatureQr, blockNumber, totalMinerNum, state)
	for i := int64(0); i <= offset.Int64(); i++ {
		if i == 0 {
			if checkAddress(state, miner, idTarget.Int64()) {
				return true, i, idTarget.Int64()
			}
		} else {
			id := calId(idTarget, preSignatureQr, totalMinerNum, big.NewInt(i), state, blockNumber)
			if checkAddress(state, miner, id.Int64()) {
				return true, i, idTarget.Int64()
			}
		}
	}
	return false, 0, 0
}

func CalIdTarget(preCoinbase common.Address, preSignatureQr []byte, blockNumber *big.Int, totalMinerNum *big.Int, state *state.StateDB) *big.Int {
	// Qr = Hash(coinbase_(r-1) || r-1 || Sig_(r-1))
	qr, _ := CalQrOrIdNext(preCoinbase.Bytes(), blockNumber, preSignatureQr)
	idTarget := new(big.Int).Mod(qr.Big(), totalMinerNum)
	// check whether the id is be punished
	idTarget = checkIdTargetOrId(state, idTarget, totalMinerNum, blockNumber)
	return idTarget
}

func calId(idTarget *big.Int, preSignatureQr []byte, totalMinerNum *big.Int, offset *big.Int, state *state.StateDB, blockNumber *big.Int) *big.Int {
	// qrOffset = hash(ID_Target_r || nλ || Sig_(r-1))
	qrOffset, _ := CalQrOrIdNext(idTarget.Bytes(), offset, preSignatureQr)
	id := new(big.Int).Mod(qrOffset.Big(), totalMinerNum)
	id = checkIdTargetOrId(state, id, totalMinerNum, blockNumber)

	// cal oldNode
	var oldNode []int64
	if offset.Int64()-1 == 0 {
		oldNode = append(oldNode, idTarget.Int64())
	} else {
		for i := ignoreSlot; i > 0; i-- {
			idNextTemp, _ := CalQrOrIdNext(idTarget.Bytes(), new(big.Int).Sub(offset, big.NewInt(i)), preSignatureQr)
			idTemp := new(big.Int).Mod(idNextTemp.Big(), totalMinerNum)
			idTemp = checkIdTargetOrId(state, idTemp, totalMinerNum, blockNumber)
			oldNode = append(oldNode, idTemp.Int64())
		}
	}
	// id can't be the same as ignoreSlot before
DONE:
	for {
		for index, value := range oldNode {
			if id.Int64() == value {
				id.Add(id, common.Big1)
				id.Mod(id, totalMinerNum)
				id = checkIdTargetOrId(state, id, totalMinerNum, blockNumber)
				break
			}
			if int64(cap(oldNode)) == int64(index+1) {
				break DONE
			}
		}
	}

	return id
}

// Check whether the miner is be punished by idOriginal , and return a right id
func checkIdTargetOrId(statedb *state.StateDB, idOriginal *big.Int, totalMinerNum *big.Int, blockNumber *big.Int) *big.Int {
	if blockNumber.Int64() < 114000 {
		var res common.Hash
		rand.Seed(blockNumber.Int64())
		for {
			res = statedb.GetState(common.Base58AddressToAddress(common.StringToBase58Address(MinerListContract)), common.HexToHash(common.IncreaseHexByNum(keyIndex, idOriginal.Int64())))
			if isPunishMiner(statedb, common.HexToAddress("0x"+res.String()[26:]), totalMinerNum, blockNumber) || !isOnLine(statedb, common.HexToAddress("0x"+res.String()[26:])) {
				idOriginal.Add(idOriginal, big.NewInt(rand.Int63n(totalMinerNum.Int64())))
				idOriginal.Mod(idOriginal, totalMinerNum)
			} else {
				return idOriginal
			}
		}
	} else {
		var res common.Hash
		i := int64(0)
		for {
			res = statedb.GetState(common.Base58AddressToAddress(common.StringToBase58Address(MinerListContract)), common.HexToHash(common.IncreaseHexByNum(keyIndex, idOriginal.Int64())))
			if isPunishMiner(statedb, common.HexToAddress("0x"+res.String()[26:]), totalMinerNum, blockNumber) || !isOnLine(statedb, common.HexToAddress("0x"+res.String()[26:])) {
				if i == 0 {
					idOriginal.Add(idOriginal, big.NewInt(0).Mod(blockNumber, totalMinerNum))
				} else {
					idOriginal.Add(idOriginal, big.NewInt(1))
				}
				i = i + 1
				idOriginal.Mod(idOriginal, totalMinerNum)
			} else {
				return idOriginal
			}
		}
	}
}

func CalQrOrIdNext(base []byte, number *big.Int, preQr []byte) (common.Hash, error) {
	/// TODO: check the preQr whether got enough length
	if len(preQr) != PreQrLength {
		return common.Hash{}, fmt.Errorf("invalid preQr length")
	}
	pub, err := crypto.Ecrecover(preQr[65:], preQr[:65])
	if err != nil {
		return common.Hash{}, fmt.Errorf("retrieve public key failed")
	}
	pubKey := crypto.ToECDSAPub(pub)

	A := new(ecdsa.PublicKey)
	A.X, A.Y = crypto.S256().ScalarMult(pubKey.X, pubKey.Y, preQr[65:])
	return crypto.Keccak256Hash(bytes.Join([][]byte{base, number.Bytes(), crypto.FromECDSAPub(A)}, []byte(""))), nil
}

func ReadMinerAddress(statedb *state.StateDB, offset int64) []byte {
	// get data from the contract statedb
	res := statedb.GetState(common.Base58AddressToAddress(common.StringToBase58Address(MinerListContract)), common.HexToHash(common.IncreaseHexByNum(keyIndex, offset)))
	return res.Bytes()
}

// Compare the address to the minerlist contract by offset
func checkAddress(statedb *state.StateDB, miner common.Address, index int64) bool {
	res := statedb.GetState(common.Base58AddressToAddress(common.StringToBase58Address(MinerListContract)), common.HexToHash(common.IncreaseHexByNum(keyIndex, index)))
	if strings.EqualFold(res.String()[26:], miner.String()[2:]) {
		return true
	}
	return false
}

// Return whether the miner is be punished or permanent penalty
func isPunishMiner(statedb *state.StateDB, miner common.Address, totalMinerNum *big.Int, blockNumber *big.Int) bool {
	if totalMinerNum.Cmp(common.Big1) < 1 {
		return false
	}

	misconducts := GetMisconducts(statedb, miner)
	switch {
	case misconducts.Int64() < common.MisconductLimitsLevel1:
		return false
	case misconducts.Int64() < common.MisconductLimitsLevel3:
		return !isThroughPenaltyBlockTime(statedb, miner, blockNumber)
	default:
		return true
	}
}

func GetMisconducts(statedb *state.StateDB, miner common.Address) *big.Int {
	web3key := paramIndexaHead + miner.Hex()[2:] + common.BigToHash(big.NewInt(4)).Hex()[2:]
	hash := sha3.NewKeccak256()
	var keyIndex []byte
	b, _ := hex.DecodeString(web3key)
	hash.Write(b)
	keyIndex = hash.Sum(keyIndex)

	// get data from the contract statedb
	return statedb.GetState(common.Base58AddressToAddress(common.StringToBase58Address(MinerListContract)), common.BytesToHash(keyIndex)).Big()
}

func isThroughPenaltyBlockTime(statedb *state.StateDB, miner common.Address, blockNumber *big.Int) bool {
	web3key := paramIndexaHead + miner.Hex()[2:] + common.BigToHash(big.NewInt(6)).Hex()[2:]
	hash := sha3.NewKeccak256()
	var keyIndex []byte
	b, _ := hex.DecodeString(web3key)
	hash.Write(b)
	keyIndex = hash.Sum(keyIndex)

	// get data from the contract statedb
	blockHeight := statedb.GetState(common.Base58AddressToAddress(common.StringToBase58Address(MinerListContract)), common.BytesToHash(keyIndex)).Big()

	if blockNumber.Int64() < common.VoteSlotForGenesis {
		if blockNumber.Int64()-blockHeight.Int64() > common.PenaltyBlockTime {
			return true
		}
	} else {
		if blockNumber.Int64()-blockHeight.Int64() > common.PenaltyBlockTimeNew {
			return true
		}
	}
	return false
}

func isOnLine(statedb *state.StateDB, miner common.Address) bool {
	web3key := paramIndexaHead + miner.Hex()[2:] + common.BigToHash(big.NewInt(5)).Hex()[2:]
	hash := sha3.NewKeccak256()

	var keyIndex []byte
	b, _ := hex.DecodeString(web3key)
	hash.Write(b)
	keyIndex = hash.Sum(keyIndex)

	// get data from the contract statedb
	return statedb.GetState(common.Base58AddressToAddress(common.StringToBase58Address(MinerListContract)), common.BytesToHash(keyIndex)).Big().Int64() == 1
}

func calKeyIndex() []byte {
	hash := sha3.NewKeccak256()
	hash.Write(hexutil.MustDecode(paramIndexFull))
	var keyIndex []byte
	keyIndex = hash.Sum(keyIndex)
	return keyIndex
}

func isOnlyOneMinerValid(state *state.StateDB, totalMinerNum *big.Int, blockNumber *big.Int) (bool, int64) {
	var validMinerNum = 0
	var index int64
	for i := int64(0); i < totalMinerNum.Int64(); i++ {
		res := state.GetState(common.Base58AddressToAddress(common.StringToBase58Address(MinerListContract)), common.HexToHash(common.IncreaseHexByNum(keyIndex, i)))
		if !isPunishMiner(state, common.HexToAddress("0x"+res.String()[26:]), totalMinerNum, blockNumber) {
			validMinerNum++
			index = i
			if validMinerNum > 1 {
				return false, 0
			}
		}
	}
	if validMinerNum == 1 {
		return true, index
	}
	return false, 0
}
