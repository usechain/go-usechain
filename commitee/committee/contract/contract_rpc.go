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
	"github.com/usechain/go-usechain/ethrpc"
	"github.com/usechain/go-usechain/log"
	//"github.com/usechain/go-usechain/core/state"
	"fmt"
	"strconv"
	"math/big"
)

const (
	oneTimeAddress = 0
	mainAddress	   = 1
	subAddress	   = 2
)

type ABaccountRequest struct {
	confirmed			uint64
	addressType 		uint64
	ringSig 			string
	pubSkey				string
	publicKeyMirror 	string
}

func transferStringToInt(str string) (uint64, bool) {
	a, err := big.NewInt(0).SetString(str, 16)
	if err == false {
		return 0, err
	}
	return a.Uint64(), true
}

func extractToOTAinfo(data string) string {
	pubPosition, _ := transferStringToInt(data[194:258])
	pubLen, _ := transferStringToInt(data[2 + 64*(pubPosition/32): 66 + 64*(pubPosition/32)])
	pubKey := data[66 + 64*(pubPosition/32):66 + 64*(pubPosition/32) + 2 * pubLen]

	log.Debug("read pubkey from contract: ", pubKey)
	return pubKey
}


func extractToABaccountRequest(data string) *ABaccountRequest {
	confirmed, _ := transferStringToInt(data[2 + 64 * 1: 66 + 64 * 1])
	addressType, _ := transferStringToInt(data[2 + 64 * 2: 66 + 64 * 2])

	ringSigPosition, _ := transferStringToInt(data[2 + 64 * 3:66 + 64 * 3])
	pubKeyPosition,_ := transferStringToInt(data[2 + 64 * 4:66 + 64 * 4])
	pubKeyMirrorPosition,_ := transferStringToInt(data[2 + 64 * 5:66 + 64 * 5])

	fmt.Println(data[2 + 64 * 3:66 + 64 * 3])
	fmt.Println(data[2 + 64 * 4:66 + 64 * 4])
	fmt.Println(data[2 + 64 * 5:66 + 64 * 5])

	ringSigLen, _ := transferStringToInt(data[2 + 64*(ringSigPosition/32): 66 + 64*(ringSigPosition/32)])
	pubKeyLen, _ := transferStringToInt(data[2 + 64*(pubKeyPosition/32): 66 + 64*(pubKeyPosition/32)])
	pubKeyMirrorLen, _ := transferStringToInt(data[2 + 64*(pubKeyMirrorPosition/32): 66 + 64*(pubKeyMirrorPosition/32)])

	ringSig := data[66 + 64*(ringSigPosition/32):66 + 64*(ringSigPosition/32) + 2 * ringSigLen]
	pubKey := data[66 + 64*(pubKeyPosition/32):66 + 64*(pubKeyPosition/32) + 2 * pubKeyLen]
	pubKeyMirror := data[66 + 64*(pubKeyMirrorPosition/32):66 + 64*(pubKeyMirrorPosition/32) + 2 * pubKeyMirrorLen]

	var ABaccount = new(ABaccountRequest)
	ABaccount.confirmed = confirmed
	ABaccount.addressType = addressType
	ABaccount.ringSig = ringSig
	ABaccount.pubSkey = pubKey
	ABaccount.publicKeyMirror = pubKeyMirror

	fmt.Println("confirmed, addressType, ringSig, Pubkey, PubKeyMirror:", confirmed, addressType, ringSig, pubKey, pubKeyMirror)
	
	return ABaccount
}

func ReadOTAccountDemo() {
	for i := 0; true; i++ {
		data := GenerateOneTimeAddressConfirmedRequest(i)
		result, err := CallToContract(AuthentcationNewContract, data)
		if err != nil {
			log.Error("CallToContract", err)
			return
		}
		fmt.Println(result)
		if result == "0x" {
			break
		}
		data2 := GenerateOneTimeAddressDetailRequest(result[2:])
		fmt.Println(data2)
		OTAinfo, err := CallToContract(AuthentcationNewContract, data2)
		if err != nil {
			log.Error("CallToContract", err)
			return
		}
		fmt.Println(OTAinfo)
		pubkey := extractToOTAinfo(OTAinfo)
		///TODO: Need to transfer the pubkey to *ecdsa.publickey
		fmt.Println("The pubkey:", pubkey)
	}
}

func IsAccountConfirmed(address string) bool{
	data := CertificateAddr(formatData64bytes(address[2:]))
	fmt.Println(data)
	result, err := CallToContract(AuthentcationNewContract, data)
	if err != nil {
		log.Error("CallToContract", err)
		return false
	}
	fmt.Println("The result",result)
	addressInfo := extractToABaccountRequest(result)

	return addressInfo.confirmed == 1
}

func ReadAccountVerify(index int) *ABaccountRequest {
	data := unConfirmedAddress(index)
	result, err := CallToContract(AuthentcationNewContract, data)
	if err != nil {
		log.Error("CallToContract", err)
		return nil
	}
	fmt.Println(result)
	if result == "0x" {
		return nil
	}
	data2 := certToaddress(result[2:])
	fmt.Println(data2)
	result, err = CallToContract(AuthentcationNewContract, data2)
	if err != nil {
		log.Error("CallToContract", err)
		return nil
	}
	fmt.Println("The result",result)

	data3 := CertificateAddr(result[2 + 64:])
	fmt.Println(data3)
	result, err = CallToContract(AuthentcationNewContract, data3)
	if err != nil {
		log.Error("CallToContract", err)
		return nil
	}
	fmt.Println("Account Request", result)
	accountInfo := extractToABaccountRequest(result)

	return accountInfo
}

func GenerateOneTimeAddressConfirmedRequest(index int) string{
	abi := "0x7120bb86" + formatData64bytes(strconv.Itoa(index))
	return abi
}

func GenerateOneTimeAddressDetailRequest(addr string) string{
	abi := "0x9b629b4b" + addr
	return abi
}

func unConfirmedAddress(index int) string {
	abi := "0xac1612a1" + formatData64bytes(strconv.Itoa(index))
	return abi
}

func certToaddress(index string) string {
	abi := "0xc8f3e94a" + index
	return abi
}

func CertificateAddr(address string) string {
	abi := "0x72884eb2" + address
	return abi
}

func CallToContract(contractAddr string, data string) (string, error) {
	client := ethrpc.New("http://127.0.0.1:8545")

	// sendTransaction to contract
	result, err := client.EthCall(ethrpc.T{
		From:  "0xfa01c38d39625a76d2f13af3203e82555236f9ea",
		To:    contractAddr,
		Data:  data,
	}, "latest")
	if err != nil {
		log.Error("Call transaction :", err)
		fmt.Println("error", err)
		return "", err
	}

	return result, nil
}

