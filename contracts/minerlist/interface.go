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
	"encoding/hex"
	"fmt"
	"github.com/usechain/go-usechain/common"
	"github.com/usechain/go-usechain/core/state"
	"github.com/usechain/go-usechain/crypto"
	"github.com/usechain/go-usechain/crypto/sha3"
	"github.com/usechain/go-usechain/log"
	"math/big"
	"math/rand"
	"strconv"
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

func CalQr(base []byte, number *big.Int, preQrSignature []byte) (common.Hash) {
	return crypto.Keccak256Hash(bytes.Join([][]byte{base, number.Bytes(), preQrSignature}, []byte("")))
}

func IsValidMiner(state *state.StateDB, miner common.Address, preCoinbase common.Address, preSignatureQr []byte, blockNumber *big.Int, totalMinerNum *big.Int, n *big.Int, preDifficultyLevel *big.Int) (bool, int64) {
	preLevel, _ := strconv.ParseFloat(preDifficultyLevel.String(),64)
	totalminernum, _ := strconv.ParseFloat(totalMinerNum.String(),64)
	minerlist := genRandomMinerList(preSignatureQr, totalMinerNum)
	qr := CalQr(preCoinbase.Bytes(), blockNumber, preSignatureQr)
	idTarget := new(big.Int).Rem(qr.Big(), totalMinerNum)
	paramIndex := "0000000000000000000000000000000000000000000000000000000000000000"
	hash := sha3.NewKeccak256()
	hash.Write(decodeHex(paramIndex))
	var keyIndex []byte
	keyIndex = hash.Sum(keyIndex)
	var oldNode []int64
	oldNode = append(oldNode, idTarget.Int64())
	var level float64
	if(preLevel > 3){
		level = 0.3
	}else{
		level = 0.1 * preLevel
	}
	for i := int64(0); i <= n.Int64(); i++ {
		if i == 0 {
			idTargetfloat, _ := strconv.ParseFloat(idTarget.String(),64)
			if preDifficultyLevel.Int64() !=0 && idTargetfloat > (float64(0.618) - level) * totalminernum {
				fmt.Println("首轮选中，但是被时间惩罚，preDifficultyLevel", preDifficultyLevel.Int64())
				continue
			}
			res := state.GetState(common.HexToAddress(MinerListContract), common.HexToHash(IncreaseHexByNum(keyIndex, minerlist[idTarget.Int64()])))
			if strings.EqualFold(res.String()[26:], miner.String()[2:]) {
				log.Info("mined by successor first in order ", "id ", minerlist[idTarget.Int64()], "address ", miner.String()[2:])
				fmt.Println("mined by successor first in order ", "id ", minerlist[idTarget.Int64()], "address ", miner.String()[2:])
				return true, i
			}
		} else {
			idn := CalQr(idTarget.Bytes(), big.NewInt(i), preSignatureQr)
			id := new(big.Int).Rem(idn.Big(), totalMinerNum)
			idfloat, _ := strconv.ParseFloat(id.String(),64)
			if preDifficultyLevel.Int64() !=0 && idfloat > (float64(0.618) - level) * totalminernum {
				fmt.Println(n, "轮选中，但是被时间惩罚，preDifficultyLevel", preDifficultyLevel.Int64())
				continue
			}
			DONE:
				for {
					for index, value := range oldNode {
						if id.Int64() == value{
							id.Add(id, common.Big1)
							id.Rem(id, totalMinerNum)
							break
						}
						if int64(cap(oldNode)) == int64(index + 1) {
							break DONE
						}
					}
					for index, value := range oldNode {
						if id.Int64() == value{
							break
						}
						if int64(cap(oldNode)) == int64(index + 1) {
							break DONE
						}
					}
				}
			res := state.GetState(common.HexToAddress(MinerListContract), common.HexToHash(IncreaseHexByNum(keyIndex, minerlist[id.Int64()])))
			if strings.EqualFold(res.String()[26:], miner.String()[2:]) {
				log.Info("mined by other successor ", "id ", minerlist[id.Int64()], "address 0x", miner.String()[2:])
				log.Info("the successor first in order ", "id", minerlist[idTarget.Int64()])
				fmt.Println("mined by other successor ", "id ", minerlist[id.Int64()], "address 0x", miner.String()[2:])
				fmt.Println("the successor first in order ", "id", minerlist[idTarget.Int64()])
				return true, i
			}
		}
	}
	return false, 0
}

func genRandomMinerList(preSignatureQr []byte, totalMinerNum *big.Int)([]int64){
	s1 := rand.NewSource(int64(binary.BigEndian.Uint64(preSignatureQr)))
	r1 := rand.New(s1)
	list := make([]int64, totalMinerNum.Int64())
	for i := int64(0); i < totalMinerNum.Int64(); i++ {
		list[i] = i
	}
	for i := int64(0); i < totalMinerNum.Int64(); i++ {
		r := r1.Int63n(totalMinerNum.Int64()-i)
		temp := list[r]
		list[r] = list[i]
		list[i] = temp
	}
	return list
}