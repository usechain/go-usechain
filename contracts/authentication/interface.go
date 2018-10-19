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

package authentication

import (
	"encoding/hex"
	"errors"
	"github.com/usechain/go-usechain/common"
	"github.com/usechain/go-usechain/crypto/sha3"
	"math/big"
	"math/rand"
	"reflect"
	"time"
	"unsafe"
)

const (
	HashLength = 32
)


// storjFlag defined the type of query data
type StorjFlag struct {
	Index 		int
	Parameter 	int
	MethodType	string
}

// a list type of query data from stateDB
var (
	// len of confirmed one time address
	OneTimeAddrConfirmedLenIndex = StorjFlag{
		Index:3,
		Parameter:0,
		MethodType:"uintValue",
	}
	// len of confirmed main address
	ConfirmedMainAddressLenIndex = StorjFlag{
		Index:4,
		Parameter:0,
		MethodType:"uintValue",
	}
	// len of confirmed sub address
	ConfirmedSubAddressLenIndex = StorjFlag{
		Index:5,
		Parameter:0,
		MethodType:"uintValue",
	}
	// len of unconfirmed address
	UnConfirmedAddressLen = StorjFlag{
		Index:6,
		Parameter:0,
		MethodType:"uintValue",
	}
	// check the committee address info
	IsCommittee = StorjFlag{
		Index:7,
		Parameter:2,
		MethodType:"mappingAddrToStruct",
	}
	// committee address listweiy
	CMMTTEEs = StorjFlag{
		Index:8,
		Parameter:15,
		MethodType:"listValue",
	}
	// public key of each committee
	CommitteePublicKey = StorjFlag{
		Index:9,
		Parameter:0,
		MethodType:"mappingAddrToString",
	}
	// mapping cert id to address
	CertToAddress = StorjFlag{
		Index:10,
		Parameter:2,
		MethodType:"mappingUintToStruct",
	}
	// confirmation of a committee
	CommitteeConfirmations = StorjFlag{
		Index:11,
		Parameter:0,
		MethodType:"mappingToMapping",
	}
	// each one time address's info
	OneTimeAddr = StorjFlag{
		Index:12,
		Parameter:4,
		MethodType:"mappingAddrToStruct",
	}
	// check if one time address confirmed
	OneTimeAddrConfirmed = StorjFlag{
		Index:13,
		Parameter:0,
		MethodType:"listValue",
	}
	// query main/sub address info
	CertificateAddr = StorjFlag{
		Index:14,
		Parameter:6,
		MethodType:"mappingAddrToStruct",
	}
	// confirmed main address list
	ConfirmedMainAddress = StorjFlag{
		Index:15,
		Parameter:0,
		MethodType:"listValue",
	}
	// confirmed sub address list
	ConfirmedSubAddress = StorjFlag{
		Index:16,
		Parameter:0,
		MethodType:"listValue",
	}
	// unconfirmed address list
	UnConfirmedAddress = StorjFlag{
		Index:17,
		Parameter:0,
		MethodType:"listValue",
	}
)

//// main entrance of query data from contract statedb, you can see details from our wiki
//func QueryDataFromStateDb(self *state.StateDB, ContractAddr common.Address, method StorjFlag, key string,pos int64) ([]byte, error) {
//	// generate a query index
//	keyIndex, err := authentication.ExpandToIndex(method, key, pos)
//	// get data from the contract statedb
//	res := self.GetState(ContractAddr, common.HexToHash(keyIndex))[:]
//	return res[:], nil
//}


// using method key & pos generate a query index
// methods: get index from StorjFlag
// key: parameter of storage type
// pos: index of state variable
func ExpandToIndex(methods StorjFlag, key string, pos int64) (string, error) {
	// change "key" to string type
	newKey := string(FromHex(key))
	// init a byte slice of hash lengths
	indexed := make([]byte, common.HashLength)
	// fill data to indexed byte slice from method index
	indexed[len(indexed)-1] = byte(methods.Index)

	// change byte slice to string type
	newIndex := hex.EncodeToString(indexed)

	switch methods.MethodType {
	// if the method is "uintValue", return the string data
	case "uintValue":
		return newIndex, nil

	case "mappingAddrToStruct":
		// expand prefix of new key, length is 32 Byte
		newKey = ExtendPrefix(newKey, 64 - len(newKey))
		// calculate statedb index from newKey
		indexKey := CalculateStateDbIndex(newKey, newIndex)
		// return data that has been added to the pos
		return IncreaseHexByNum(indexKey, pos), nil

	case "mappingAddrToString":
		newKey = ExtendPrefix(newKey, 64 - len(newKey))
		indexKey := CalculateStateDbIndex(newKey, newIndex)
		return hex.EncodeToString(indexKey), nil

	case "mappingUintToStruct":
		newKey = ExtendPrefix(newKey, 64 - len(newKey))
		indexKey := CalculateStateDbIndex(newKey, newIndex)
		return IncreaseHexByNum(indexKey, pos), nil
		// not working yet
	case "mappingToMapping":
		return "", errors.New("method is not working yet")

	case "listValue":
		if key != "" {
			key = ""
		}
		indexKey := CalculateStateDbIndex(key, newIndex)
		return IncreaseHexByNum(indexKey, pos), nil
	}
	return "", errors.New("no method matched")
}

// extend the len of key
func ExtendPrefix(key string, num int) string {
	preZero := ""
	for i := 0; i < num; i++ {
		preZero += "0"
	}
	key = preZero + key
	return key
}

// change key's type to string
func FromHex(key string) string {
	if key == "" {
		return key
	}
	if key[0:2] == "0x" || key[0:2] == "0X" {
		key = key[2:]
	}
	if len(key) %2 == 1 {
		key = "0" + key
	}
	return key
}

// return the string data that has been added to the num
func IncreaseHexByNum(indexKeyHash []byte, num int64) string {
	x := big.NewInt(0)
	y := big.NewInt(int64(num))
	x.SetBytes(indexKeyHash)
	x.Add(x, y)
	return hex.EncodeToString(x.Bytes())
}

// calculate the statedb index from key and parameter
func CalculateStateDbIndex(key string, paramIndex string) []byte {
	web3key := key + paramIndex
	hash := sha3.NewKeccak256()
	var keyIndex []byte
	hash.Write(decodeHexFromString(web3key))
	keyIndex = hash.Sum(keyIndex)
	return keyIndex
}

// decode string data to hex
func decodeHexFromString(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// generate a random number from a range
func GenerateRandomNumber(numRange int64) int64 {
	seed := time.Now().UnixNano()
	src := rand.NewSource(seed)
	randNum := rand.New(src)
	return randNum.Int63n(numRange)
}

// get byte data length
func GetLen(lenByte []byte) int64 {
	b := big.NewInt(0)
	b.SetBytes(lenByte)
	return b.Int64()
}


func BytesToString(byteData []byte) string {
	bh := (*reflect.SliceHeader)(unsafe.Pointer(&byteData))
	sh := reflect.StringHeader{bh.Data, bh.Len}
	return *(*string)(unsafe.Pointer(&sh))
}
