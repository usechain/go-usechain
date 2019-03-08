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
	"fmt"
	"github.com/usechain/go-usechain/common"
	"github.com/usechain/go-usechain/core/state"
	"github.com/usechain/go-usechain/crypto/sha3"
)

// storjFlag defined the type of query data
type StorjFlag struct {
	Index 		int
	Parameter 	int
	MethodType	string
}

//Get key index of certificateAddr
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

//Check the address whether is verified AB account
func IsMultiAccountConfirmed(db *state.StateDB, _addr common.Address) bool {
	key := ReadCertificateAddr(_addr.Hex()[2:])
	res := db.GetState(common.HexToAddress(common.AuthenticationContractAddressString), common.HexToHash(key))

	return res.Hex() != state.StatDbEmpty
}

//Check the address authentication state
func CheckAddrAuthenticateStat(db *state.StateDB, _addr common.Address) int {
	if IsMultiAccountConfirmed(db, _addr) {
		return 1
	}
	return 0
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

// decode hex string to []byte
func decodeHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

//expand hex string to 64 with '0' prefix
func formatData64bytes(_data string) string{
	dataRawlength := len(_data);

	if dataRawlength > 64 {
		fmt.Println("the string is explicit the length")
		return _data;
	}
	for index := 0; index < 64 - dataRawlength; index++ {
		_data = "0" + _data;
	}
	return _data
}