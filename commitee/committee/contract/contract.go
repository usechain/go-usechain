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
	"fmt"

	"github.com/usechain/go-usechain/crypto/sha3"
	"encoding/hex"
)

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

