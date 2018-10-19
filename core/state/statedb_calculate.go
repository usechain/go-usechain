
//@Time  : 2018/3/14 11:34
//@Author: lyszhang
package state

import (
	"encoding/hex"
	"fmt"
	"github.com/usechain/go-usechain/crypto/sha3"
)

func FormatData64bytes(_data string) string {
	return formatData64bytes(_data)
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

func DecodeHex(s string) []byte {
	return decodeHex(s)
}

func decodeHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func CalculateStatdbIndex(key string, paramIndex string) []byte {
	return calculateStatedbIndex(key, paramIndex)
}

func calculateStatedbIndex(key string, paramIndex string) []byte {
	key = formatData64bytes(key);
	paramIndex = formatData64bytes(paramIndex);
	web3key := key + paramIndex;

	fmt.Println("The web3db key is", web3key)

	hash := sha3.NewKeccak256()

	var keyIndex []byte
	hash.Write(decodeHex(web3key))
	keyIndex = hash.Sum(keyIndex)

	fmt.Println(hex.EncodeToString(keyIndex))

	return keyIndex
}




