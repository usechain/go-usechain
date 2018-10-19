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
//
// Author: lyszhang
// Time:   2018/07/11
// Description: Committee read ABaccount verify info, scan the accounts & change the AB account verify stat
//    		    A1 = [hash(bA)]G + S = [hash(aB)]G + S

package contract

import (
	"crypto/ecdsa"
	"fmt"

	"github.com/usechain/go-usechain/crypto"
	//"github.com/usechain/go-usechain/common"
	"github.com/usechain/go-usechain/common/hexutil"
	"github.com/usechain/go-usechain/ethrpc"
	"github.com/usechain/go-usechain/log"
	"github.com/usechain/go-usechain/crypto/sha3"
	"encoding/hex"
	"math/big"
)

const (
	AuthentcationNewContract = "0xA29c016C8452Fbc2b532f08811CF0B47d5B0CDcc"
)

type oneTimeAddr struct{
	confirmed uint
	caSign    string
	certMsg	  string
	pubkey    string
}

func decodeHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func formatData64bytes(_data string) string{
	dataRawlength := len(_data);

	if dataRawlength > 64 {
		fmt.Println("the string is explicit the length")
		return _data;
	}
	for index := 0; index < 64 - dataRawlength; index++ {
		_data = "0" + _data;
	}
	//fmt.Println("The data is :", _data);
	return _data
}

func ReadUnverifiedAccount() (*ecdsa.PublicKey, *ecdsa.PublicKey){
	A1str := "0x04dded5fe2be778b31fad7472d2c3272e23f9995344be27a587af2b597f05faf5621858e79a25797a85b6e089b6f7ba859bdeb0e4f115f2441fce2ca071bf5c7f7"
	Sstr := "0x0410286e52cf87851e27a945434700d969ebb4fcd165b1c95edecdde8e4c104938785700797b6579c731f81c9696ba63aea571eca00767175cdb62e3f9284f4a52"

	A1, _ := hexutil.Decode(A1str)
	S, _ := hexutil.Decode(Sstr)

	return crypto.ToECDSAPub(A1), crypto.ToECDSAPub(S)
}

func ReadMainAccount() ([]string) {
	Astr := []string{
		"0x049a0b2c928af39a0dd635702e920864d16ec9846d1517a5e181792d4b84943688746359d46c49045d42b550a27f464919c1838f93d478750deeec48a8a9db12a6",
	}
	return Astr
}

func ReadOTAccount() {
	key := ReadOneTimeAddressConfirmed()
	for ;; {
		result, err := GetStateAt(AuthentcationNewContract, key.Text(16))
		if err != nil {
			log.Error("GetStateAt failed!")
		}
		if result == "0x0000000000000000000000000000000000000000000000000000000000000000" {
			break
		}

		OTAddress := result[26:]
		OTAinfo := ReadOneTimeAddressDetail(OTAddress)

		result, err = GetStateAt(AuthentcationNewContract, OTAinfo)
		if err != nil {
			log.Error("GetStateAt failed!")
		}

		key.Add(key, big.NewInt(1))
	}
}

func ReadCommitteePrivatekey() ([]byte) {
	bStr := "0x3d1f7b376c2a9a58fe9ee622f4bc1886a3d8be4eee409ebf3d5b54053295f705"
	b, _ := hexutil.Decode(bStr)
	return  b
}

func ReadOneTimeAddressConfirmed() *big.Int{
	index := "000000000000000000000000000000000000000000000000000000000000000d";
	hash := sha3.NewKeccak256()

	var keyIndex []byte
	hash.Write(decodeHex(index))
	keyIndex = hash.Sum(keyIndex)

	fmt.Println(hex.EncodeToString(keyIndex))
	key,_ := big.NewInt(0).SetString(hex.EncodeToString(keyIndex), 16)
	return key
}

func ReadOneTimeAddressDetail(key string) string {
	key = formatData64bytes(key);
	paramIndex := "000000000000000000000000000000000000000000000000000000000000000c";
	web3key := key + paramIndex;

	hash := sha3.NewKeccak256()

	var keyIndex []byte
	hash.Write(decodeHex(web3key))
	keyIndex = hash.Sum(keyIndex)

	return hex.EncodeToString(keyIndex)
}

func ReadCertificateAddr(key string) string {
	key = formatData64bytes(key);
	paramIndex := "000000000000000000000000000000000000000000000000000000000000000e";
	web3key := key + paramIndex;

	hash := sha3.NewKeccak256()

	var keyIndex []byte
	hash.Write(decodeHex(web3key))
	keyIndex = hash.Sum(keyIndex)

	return hex.EncodeToString(keyIndex)
}

func ReadIsCommitteeAddr(key string) string {
	key = formatData64bytes(key);
	paramIndex := "0000000000000000000000000000000000000000000000000000000000000007";
	web3key := key + paramIndex;

	hash := sha3.NewKeccak256()

	var keyIndex []byte
	hash.Write(decodeHex(web3key))
	keyIndex = hash.Sum(keyIndex)

	return hex.EncodeToString(keyIndex)
}

func GenerateConfirmAccountData(certID uint, confirm uint) string {
	data := "0xc03c1796" + formatData64bytes(string(certID)) + formatData64bytes(string(confirm))
	return data
}

func SendRequestToContract(contractAddr string, data string) error {
	client := ethrpc.New("http://127.0.0.1:8545")

	// sendTransaction to contract
	txid, err := client.EthSendTransaction(ethrpc.T{
		From:  "0xfa01c38d39625a76d2f13af3203e82555236f9ea",
		To:    contractAddr,
		Data:  data,
	})
	if err != nil {
		log.Error("SendTransaction:", err)
		return err
	}
	fmt.Println(txid)
	return nil
}

func GetStateAt(contractAddr string, key string) (string, error) {
	client := ethrpc.New("http://127.0.0.1:8545")

	result, err := client.EthGetStorageAt2(contractAddr, key, "latest")
	if err != nil {
		log.Error("SendTransaction:", err)
		return "", err
	}
	fmt.Println(result)
	return result, nil
}