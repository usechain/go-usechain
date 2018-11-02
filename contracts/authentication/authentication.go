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
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/usechain/go-usechain/common"
	"github.com/usechain/go-usechain/common/hexutil"

	"github.com/usechain/go-usechain/accounts/keystore"
	"github.com/usechain/go-usechain/core/state"
	"github.com/usechain/go-usechain/crypto"
	"github.com/usechain/go-usechain/crypto/sha3"
	"github.com/usechain/go-usechain/log"
	"math/big"
	"math/rand"
	"reflect"
	"strings"
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



func GetUnconfirmedAddrInterface(self *state.StateDB, contractAddr common.Address, addrLen int64) ([]byte, error) {
	// generate a query index
	keyIndex4, _ := ExpandToIndex(OneTimeAddrConfirmedLenIndex, "", 0)
	// get data from the contract statedb
	//resultOneTimeAddrLen := self.GetState(contractAddr, common.HexToHash(keyIndex4))
	resultOneTimeAddrLen := self.GetState(contractAddr, common.HexToHash(keyIndex4))
	return resultOneTimeAddrLen[:], nil
}

func GetUnConfirmedMainInfoInterface(self *state.StateDB, contractAddr common.Address, PubKeyLen int64,pos int64) (string, error) {
	// generate key
	//pos = 1 ringsig
	//pos = 2 ASkey
	//pos = 3 keyImage

	keyIndex, _ := ExpandToIndex(UnConfirmedAddressLen, "", 0)
	resultUnConfirmedAddressLen := self.GetState(contractAddr, common.HexToHash(keyIndex))
	unConfirmedAddressLen := GetLen(resultUnConfirmedAddressLen[:])
	fmt.Println("unConfirmedAddressLen: ", unConfirmedAddressLen)
	if unConfirmedAddressLen == 0 {
		fmt.Println("No unConfirmedAddress")
		return "",nil
	}

	// get unConfirmedAddress data
	res := ""
	for i := int64(0); i < unConfirmedAddressLen; i++ {

		// generate i's keyindex to check unconfirmed address index
		keyIndex, _ := ExpandToIndex(UnConfirmedAddress, "", i)
		resultUnConfirmedAddressIndex :=self.GetState(contractAddr, common.HexToHash(keyIndex))
		//unConfirmedAddressIndex := state.G etLen(resultUnConfirmedAddressIndex[:])
		fmt.Println("unconfirmed address index: ", resultUnConfirmedAddressIndex)

		// generate unConfirmedAddress indexed key
		newKeyIndex, _ := ExpandToIndex(CertToAddress, hex.EncodeToString(resultUnConfirmedAddressIndex[:]), 0)
		resultUnConfirmedAddress := self.GetState(contractAddr, common.HexToHash(newKeyIndex))
		resultUnConfirmedAddr := hex.EncodeToString(resultUnConfirmedAddress[:])
		fmt.Println("resultUnConfirmedAddress: ", "00"+resultUnConfirmedAddr[:len(resultUnConfirmedAddr)-2])

		// get ringSig
		resultRingSig, _ := ExpandToIndex(CertificateAddr, "00"+resultUnConfirmedAddr[:len(resultUnConfirmedAddr)-2], 1)
		addressRingSig := self.GetState(contractAddr, common.HexToHash(resultRingSig))
		addressRingSigLen := GetLen(addressRingSig[:])
		forLen := addressRingSigLen / (int64(common.HashLength) * 2)
		// init query data hash
		var buff bytes.Buffer
		for j := int64(0); j <= forLen; j++ {
			newKeyIndexHash := CalculateStateDbIndex(resultRingSig, "")
			newKeyIndexString := IncreaseHexByNum(newKeyIndexHash, j)
			result := self.GetState(contractAddr, common.HexToHash(newKeyIndexString))
			buff.Write(result[:])
		}
		res += buff.String()[:addressRingSigLen/2]
		fmt.Println("addressRingSig: ", res)

		// get pubSkey
		resultPubSKey, _ := ExpandToIndex(CertificateAddr, "00"+resultUnConfirmedAddr[:len(resultUnConfirmedAddr)-2], 2)
		addressPubSKey := self.GetState(contractAddr, common.HexToHash(resultPubSKey))

		addressPubSKeyLen := GetLen(addressPubSKey[:])
		forLen1 := addressPubSKeyLen / (int64(common.HashLength) * 2)
		var buff1 bytes.Buffer
		res1 := ""
		for j := int64(0); j <= forLen1; j++ {
			newKeyIndexHash := CalculateStateDbIndex(resultPubSKey, "")
			newKeyIndexString := IncreaseHexByNum(newKeyIndexHash, j)
			result := self.GetState(contractAddr, common.HexToHash(newKeyIndexString))
			buff1.Write(result[:])
		}
		res1 += buff1.String()[:addressPubSKeyLen/2]
		fmt.Println("addressPubSKey: ", res1)
	}
	return res, nil
}

type cachedRandomNumber map[int64]bool
func GetOneTimePubSetInterface(self *state.StateDB, contractAddr common.Address, PubKeyLen int64) (string, error)  {
	// check if the value of Pubkeylen is 0
	if PubKeyLen == 0 {
		return "", errors.New("Require PubKeyLen is nonzero.")
	}

	// generate a query index
	keyIndex1, _ := ExpandToIndex(OneTimeAddrConfirmedLenIndex, "", 3)
	// get data from the contract statedb
	resultOneTimeAddrLen := self.GetState(contractAddr, common.HexToHash(keyIndex1))

	log.Info("Query result: ", "resultOneTimeAddrLen: ", resultOneTimeAddrLen[:])

	// get one time address length from string
	oneTimeAddrLen := GetLen(resultOneTimeAddrLen[:])
	if oneTimeAddrLen < PubKeyLen {
		return "", errors.New("PubKeyLen is too large")
	}

	var res = ""
	randomExist := cachedRandomNumber{}
	for  i := int64(0); i < PubKeyLen; i++ {
		// generate int64 random number in range of oneTimeAddrLen
		randomNumber := GenerateRandomNumber(oneTimeAddrLen)
		for ; randomExist[randomNumber] == true ;  {
			randomNumber = GenerateRandomNumber(oneTimeAddrLen)
		}
		log.Info("Ringsig publickey random number: ", "number", randomNumber)

		// get data string from stateDb
		// generate a query index
		keyIndex2, _ := ExpandToIndex(OneTimeAddrConfirmed, "", randomNumber)
		// get data from the contract statedb
		confirmedOneTimeAddr := self.GetState(contractAddr, common.HexToHash(keyIndex2))

		log.Info("confirmedOneTimeAddr: ","address: ", hex.EncodeToString(confirmedOneTimeAddr[:]))

		// generate a query index
		keyIndex3, _ := ExpandToIndex(OneTimeAddr, hex.EncodeToString(confirmedOneTimeAddr[:]), 3)
		// get data from the contract statedb
		resIndex := self.GetState(contractAddr, common.HexToHash(keyIndex3))

		eachPublicKeyLen := GetLen(resIndex[:])

		if eachPublicKeyLen < common.HashLength {
			return hex.EncodeToString(resIndex[:eachPublicKeyLen]),nil
		}
		forLen := eachPublicKeyLen / (int64(common.HashLength)*2)

		// init query data hash
		oneTimeAddrHash, _ := ExpandToIndex(OneTimeAddr, hex.EncodeToString(confirmedOneTimeAddr[:]), 3)

		newKeyIndex := CalculateStateDbIndex(oneTimeAddrHash, "")
		var buff bytes.Buffer
		for j := int64(0); j <=  forLen; j++ {
			newKeyIndexString := IncreaseHexByNum(newKeyIndex, j)
			result := self.GetState(contractAddr, common.HexToHash(newKeyIndexString))
			buff.Write(result[:])
			//res += BytesToString(result[:])
		}
		randomExist[randomNumber] = true
		res += buff.String()[:eachPublicKeyLen/2] + ","
		//fmt.Println("res: ", res)
	}

	return res[:len(res)-1], nil
}

func GetConfirmedMainInfoInterface(self *state.StateDB, contractAddr common.Address, keyLen int64, pos int64) (string, error) {
	// generate key
	//pos = 1 ringsig
	//pos = 2 ASkey
	//pos = 3 keyImage
	keyIndex, _ := ExpandToIndex(ConfirmedMainAddressLenIndex, "", 0)
	resultConfirmedAddressLen := self.GetState(contractAddr, common.HexToHash(keyIndex))
	ConfirmedAddressLen := GetLen(resultConfirmedAddressLen[:])
	fmt.Println("ConfirmedAddressLen: ", ConfirmedAddressLen)
	if ConfirmedAddressLen == 0 {
		fmt.Println("No ConfirmedAddress")
		return "", nil
	}

	var res = ""
	for  i := int64(0); i < keyLen; i++ {
		// get data string from stateDb

		// generate a query index
		keyIndex5, _ := ExpandToIndex(ConfirmedMainAddress, "", i)
		// get data from the contract statedb
		confirmedMainAddr := self.GetState(contractAddr, common.HexToHash(keyIndex5))

		log.Info("confirmedMainAddr: ", hex.EncodeToString(confirmedMainAddr[:]))

		// generate a query index
		keyIndex6, _ := ExpandToIndex(CertificateAddr, hex.EncodeToString(confirmedMainAddr[:]), pos)
		// get data from the contract statedb
		resIndex := self.GetState(contractAddr, common.HexToHash(keyIndex6))

		eachPublicKeyLen := GetLen(resIndex[:])
		fmt.Println("eachPublickeyLen: ", eachPublicKeyLen)
		if eachPublicKeyLen < common.HashLength {
			return hex.EncodeToString(resIndex[:eachPublicKeyLen]),nil
		}
		forLen := eachPublicKeyLen / (int64(common.HashLength)*2)

		// init query data hash
		mainAddrHash, _ := ExpandToIndex(CertificateAddr, hex.EncodeToString(confirmedMainAddr[:]), pos)
		fmt.Println("oneTimeAddrHash: ", mainAddrHash)
		newKeyIndex := CalculateStateDbIndex(mainAddrHash, "")
		var buff bytes.Buffer
		for j := int64(0); j <=  forLen; j++ {
			newKeyIndexString := IncreaseHexByNum(newKeyIndex, j)
			result := self.GetState(contractAddr, common.HexToHash(newKeyIndexString))
			buff.Write(result[:])
			//res += BytesToString(result[:])
		}
		res += buff.String()[:eachPublicKeyLen/2] + ","
		fmt.Println("res: ", res[:len(res)-1])
	}
	return res[:len(res)-1], nil
}

func GetConfirmedMainASInterface(self *state.StateDB, contractAddr common.Address, keyLen int64,pos int64) (string,error) {
	// generate key
	//pos = 1 ringsig
	//pos = 2 ASkey
	//pos = 3 keyImage

	keyIndex, _ := ExpandToIndex(ConfirmedMainAddressLenIndex, "", 0)
	resultConfirmedAddressLen := self.GetState(contractAddr, common.HexToHash(keyIndex))
	ConfirmedAddressLen := GetLen(resultConfirmedAddressLen[:])
	fmt.Println("ConfirmedAddressLen: ", ConfirmedAddressLen)
	if ConfirmedAddressLen == 0 {
		fmt.Println("No ConfirmedAddress")
		return "", nil
	}

	var res = ""
	for  i := int64(0); i < keyLen; i++ {
		// get data string from stateDb
		keyIndex6, _ := ExpandToIndex(ConfirmedMainAddress, "", i)
		// get data from the contract statedb
		confirmedMainAddr := self.GetState(contractAddr, common.HexToHash(keyIndex6))

		fmt.Println("confirmedMainAddr: ", hex.EncodeToString(confirmedMainAddr[:]))



		keyIndex7, _ := ExpandToIndex(CertificateAddr, hex.EncodeToString(confirmedMainAddr[:]), 2)
		// get data from the contract statedb
		resIndex := self.GetState(contractAddr, common.HexToHash(keyIndex7))

		eachPublicKeyLen := GetLen(resIndex[:])
		fmt.Println("eachPublickeyLen: ", eachPublicKeyLen)
		if eachPublicKeyLen < common.HashLength {
			return hex.EncodeToString(resIndex[:eachPublicKeyLen]),nil
		}
		forLen := eachPublicKeyLen / (int64(common.HashLength)*2)

		// init query data hash
		mainAddrHash, _ := ExpandToIndex(CertificateAddr, hex.EncodeToString(confirmedMainAddr[:]), 2)
		fmt.Println("oneTimeAddrHash: ", mainAddrHash)
		newKeyIndex := CalculateStateDbIndex(mainAddrHash, "")
		var buff bytes.Buffer
		for j := int64(0); j <=  forLen; j++ {
			newKeyIndexString := IncreaseHexByNum(newKeyIndex, j)
			result := self.GetState(contractAddr, common.HexToHash(newKeyIndexString))
			buff.Write(result[:])
			//res += BytesToString(result[:])
		}
		res += buff.String()[:eachPublicKeyLen/2] + ","
		fmt.Println("res: ", res[:len(res)-1])
	}
	return res[:len(res)-1], nil
}

//Get onetime address publickeys set from statedb and generate main address ring signature data
func GenRingSignData(msg, privateKey, addr string, statedb *state.StateDB) (string, string, error) {

	//Get public keys from contract.
	var ContractAddr common.Address
	ContractAddr2, _ := hexutil.Decode(common.AuthenticationContractAddressString)
	copy(ContractAddr[:], ContractAddr2)
	//publickeys, err := statedb.GetOneTimePubSet(ContractAddr, 5)
	publickeys, err := GetOneTimePubSetInterface(statedb, ContractAddr, 5)


	ringsig, keyImage, err := crypto.GenRingSignData(msg, privateKey, publickeys)
	if err != nil {
		log.Error("ringsing error: ", "err", err)
		return "", "", err
	}

	resul := crypto.VerifyRingSign(addr, ringsig)
	log.Info("verify ringsig: ", "result", resul)

	return ringsig, keyImage, nil
}

//Get main address publickeys set from statedb and generate  ring signature data of sub address authentication
func GenSubRingSignData(msg, privateKey, addr string, statedb *state.StateDB) (string, string, error) {

	//Get public keys from contract.
	var ContractAddr common.Address
	ContractAddr2, _ := hexutil.Decode(common.AuthenticationContractAddressString)
	copy(ContractAddr[:], ContractAddr2)

	//ASset, err := statedb.GetConfirmedMainAS(ContractAddr, 5, 1)
	ASset, err := GetConfirmedMainASInterface(statedb, ContractAddr, 5, 1)
	if err != nil {
		return "", "", err
	}

	ASslice := strings.Split(ASset, ",")
	publicKeyset := make([]string, 0)
	for _, AS := range ASslice {
		ASbyte, _ := hex.DecodeString(AS)
		pk1, _, err := keystore.GeneratePKPairFromABaddress(ASbyte)
		if err != nil {
		}
		pub := common.ToHex(crypto.FromECDSAPub(pk1))
		publicKeyset = append(publicKeyset, pub)
	}
	publickeys := strings.Join(publicKeyset, ",")

	ringsig, keyImage, err := crypto.GenRingSignData(msg, privateKey, publickeys)
	if err != nil {
		log.Error("ringsing error: ", "err", err)
	}

	resul := crypto.VerifyRingSign(addr, ringsig)
	log.Info("Verify ringsig: ", "result", resul)

	return ringsig, keyImage, nil
}


func ReadUnconfirmedAddressInterface(managedState *state.ManagedState, index int64, contractAddr common.Address, checkCertID int64) (string, string, string, int64){
	// generate i's keyindex to check unconfirmed address index
	keyIndex, _ := ExpandToIndex(UnConfirmedAddress, "", index)
	resultUnConfirmedAddressIndex := managedState.GetState(contractAddr, common.HexToHash(keyIndex))
	unConfirmedAddressIndex := GetLen(resultUnConfirmedAddressIndex[:])
	log.Info("unconfirmed address", "index", resultUnConfirmedAddressIndex.String())

	// check added
	if  checkCertID >= unConfirmedAddressIndex {
		return resultUnConfirmedAddressIndex.String(), "", "", 0
	}

	// generate unConfirmedAddress indexed key
	newKeyIndex, _ := ExpandToIndex(CertToAddress, hex.EncodeToString(resultUnConfirmedAddressIndex[:]), 0)
	resultUnConfirmedAddress := managedState.GetState(contractAddr, common.HexToHash(newKeyIndex))
	resultUnConfirmedAddr := hex.EncodeToString(resultUnConfirmedAddress[:])
	log.Info("resultUnConfirmed", "address", "00"+resultUnConfirmedAddr[:len(resultUnConfirmedAddr)-2])

	// get ringSig
	resultRingSig, _ := ExpandToIndex(CertificateAddr, "00"+resultUnConfirmedAddr[:len(resultUnConfirmedAddr)-2], 1)
	addressRingSig := managedState.GetState(contractAddr, common.HexToHash(resultRingSig))
	addressRingSigLen := GetLen(addressRingSig[:])
	forLen := addressRingSigLen / (int64(common.HashLength) * 2)
	// init query data hash
	var buff bytes.Buffer
	res := ""
	for j := int64(0); j <= forLen; j++ {
		newKeyIndexHash := CalculateStateDbIndex(resultRingSig, "")
		newKeyIndexString := IncreaseHexByNum(newKeyIndexHash, j)
		result := managedState.GetState(contractAddr, common.HexToHash(newKeyIndexString))
		buff.Write(result[:])
	}
	res += buff.String()[:addressRingSigLen/2]
	log.Info("address", "RingSig", res)

	// get pubSkey
	resultPubSKey, _ := ExpandToIndex(CertificateAddr, "00"+resultUnConfirmedAddr[:len(resultUnConfirmedAddr)-2], 2)
	addressPubSKey := managedState.GetState(contractAddr, common.HexToHash(resultPubSKey))

	addressPubSKeyLen := GetLen(addressPubSKey[:])
	forLen1 := addressPubSKeyLen / (int64(common.HashLength) * 2)
	var buff1 bytes.Buffer
	res1 := ""
	for j := int64(0); j <= forLen1; j++ {
		newKeyIndexHash := CalculateStateDbIndex(resultPubSKey, "")
		newKeyIndexString := IncreaseHexByNum(newKeyIndexHash, j)
		result := managedState.GetState(contractAddr, common.HexToHash(newKeyIndexString))
		buff1.Write(result[:])
	}
	res1 += buff1.String()[:addressPubSKeyLen/2]
	checkCertID = unConfirmedAddressIndex
	return resultUnConfirmedAddressIndex.String(), res, res1, checkCertID
}


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
