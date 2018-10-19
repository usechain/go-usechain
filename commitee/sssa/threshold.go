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

package sssa

import (
	"fmt"
	"github.com/usechain/go-usechain/crypto"
	"crypto/ecdsa"
	"math/big"
	"github.com/usechain/go-usechain/common"
	"github.com/usechain/go-usechain/common/hexutil"
	"github.com/usechain/go-usechain/accounts/keystore"
)

var Sharespart []*big.Int = make([]*big.Int, 3)

func generatePrivKey(key *big.Int) *ecdsa.PrivateKey {
	priv := new(ecdsa.PrivateKey)
	priv.PublicKey.Curve = crypto.S256()
	priv.D = key.Mod(key, crypto.S256().Params().N)
	priv.PublicKey.X, priv.PublicKey.Y = crypto.S256().ScalarBaseMult(key.Bytes())

	return priv
}

//count sA
func multiPub(s []byte, A *ecdsa.PublicKey) *ecdsa.PublicKey {
	A1 := new(ecdsa.PublicKey)
	A1.Curve = crypto.S256()
	//以A为基点加s次
	A1.X, A1.Y = crypto.S256().ScalarMult(A.X, A.Y, s)   //A1=[s]B
	return A1
}

//P_i select polynomial of degree k-1
//And generate shares for P_j
func GenerateShares(minimum int, shares int) ([]ecdsa.PublicKey,[]*big.Int) {
	created, pointer, polynomial, err := CreateFromInt(minimum, shares)
	if err != nil {
		fmt.Println("Fatal: creating: ", err)
	}

	var pubArray []ecdsa.PublicKey
	for k := range polynomial {
		fmt.Printf( "The polynomial: %x,%d\n", polynomial[k],k)
		priv := generatePrivKey(polynomial[k])
		pubArray = append(pubArray, priv.PublicKey)
		fmt.Printf("The public key is :%x\n", pubArray[k])
	}

	pubSum := new(ecdsa.PublicKey)
	pubSum.Curve = crypto.S256()

	for k := range polynomial {
		if k == 0 {
			pubSum.X = pubArray[0].X
			pubSum.Y = pubArray[0].Y
			continue
		}
		pubSum.X, pubSum.Y = crypto.S256().Add(pubSum.X, pubSum.Y, pubArray[k].X, pubArray[k].Y)
	}
	fmt.Printf("The sum key is:%x\n\n\n", pubSum)


	for j := range pointer {
		//fmt.Println("The created num:", created[j],)
		priv := generatePrivKey(pointer[j])
		pubKey := priv.PublicKey
		fmt.Printf("The pointer is %d, %x, :%x\n", j+1, pointer[j], pubKey)
	}
	combined, err := Combine(created)
	fmt.Println("The combined num:", combined)
	if err != nil {
		fmt.Println("Fatal: combining: ", err)
	}


	return pubArray, pointer
}

func GenerateSubAccountShares(serverId uint16) *ecdsa.PublicKey {
	sharePriv := ReadSelfshares(serverId)
	mainAccountPub := GetMainAccountPub()
	shareData := CountSubAccountSharePart(sharePriv, mainAccountPub)
	fmt.Println("GenerateSubAccountShares:", shareData)

	return shareData
}

func expontUint16(x uint16, y int) int {
	z := x
	for i := 1; i < y; i++ {
		z = z * x
	}
	return int(z)
}

func Checkshares(polynomial []PolynomialMsg, pointYstr string,  serverId uint16, senderId uint16) {
	var polynomialInt []ecdsa.PublicKey = make([]ecdsa.PublicKey, len(polynomial))

	for i := range polynomial {
		polynomialInt[i].Curve = crypto.S256()
		polynomialInt[i].X = fromBase64(polynomial[i].X)
		polynomialInt[i].Y = fromBase64(polynomial[i].Y)
		fmt.Printf("%x, %x\n", polynomialInt[i].X, polynomialInt[i].Y)
	}
	fmt.Printf("%x\n", fromBase64(pointYstr))

	pubSum := new(ecdsa.PublicKey)
	pubSum.Curve = crypto.S256()
	for j := range polynomialInt {
		fmt.Println(polynomialInt[j].X, polynomialInt[j].Y)
		if j == 0 {
			pubSum.X = polynomialInt[j].X
			pubSum.Y = polynomialInt[j].Y
			continue
		}
		for k := 0; k < expontUint16(serverId, j); k++ {
			pubSum.X, pubSum.Y = crypto.S256().Add(pubSum.X, pubSum.Y, polynomialInt[j].X, polynomialInt[j].Y)
		}

	}
	fmt.Printf("The sum key is:%x\n\n\n", pubSum)

	priv := generatePrivKey(fromBase64(pointYstr))
	pubKey := priv.PublicKey
	fmt.Printf("The pubkey is %x\n", pubKey)

	if pubSum.X.Cmp(pubKey.X) == 0 && pubSum.Y.Cmp(pubKey.Y) == 0 {
		fmt.Println("The shares is legal!")
	}else {
		fmt.Println("::::::::::::::::::::::The shares is illegal!")
	}

	// ...add it to results...
	fmt.Println("the id is", senderId-1)
	Sharespart[senderId-1] = fromBase64(pointYstr)
	return
}

func HandleSubAccountVerifyRequest(polynomial []PolynomialMsg, serverId uint16, senderId uint16, serverPort uint16) {
	var polynomialInt []ecdsa.PublicKey = make([]ecdsa.PublicKey, len(polynomial))

	for i := range polynomial {
		polynomialInt[i].Curve = crypto.S256()
		polynomialInt[i].X = fromBase64(polynomial[i].X)
		polynomialInt[i].Y = fromBase64(polynomial[i].Y)
		fmt.Printf("%x, %x\n", polynomialInt[i].X, polynomialInt[i].Y)
	}

	if serverId == 1 {
		SPub := GetSAccountPub()
		fmt.Println(crypto.GenerateSubAccount(&polynomialInt[0], SPub).Hex())

		A1Raw := GeneratePubFromStr("0x04dded5fe2be778b31fad7472d2c3272e23f9995344be27a587af2b597f05faf5621858e79a25797a85b6e089b6f7ba859bdeb0e4f115f2441fce2ca071bf5c7f7")
		addressRaw := crypto.PubkeyToAddress(*A1Raw).Hex()
		fmt.Println(addressRaw)
	}else {
		pubSum := GenerateSubAccountShares(serverId)   //tA
		pubSum.X = polynomialInt[0].X
		pubSum.Y = polynomialInt[0].Y

		fmt.Printf("The sum key is:%x\n\n\n", pubSum)
		destID, destPoint := GetDestNode(serverPort, serverId)
		SendVerifyMsg(destPoint, destID, pubSum)
	}

	return
}


func CountSharesPart(id uint16) {
	shareSum := big.NewInt(0)

	for i := range Sharespart {
		shareSum.Add(shareSum, Sharespart[i])
	}

	// ...add it to results...
	result := ToBase64(big.NewInt(int64(id)))
	result += ToBase64(shareSum)
	fmt.Println("The shares base64: ", result)
}

func ReadSelfshares(id uint16) *big.Int {
	shares := []string{
		"3d1f7b376c2a9a58fe9ee622f4bc1886a3d8be4eee409ebf3d5b54053295f705",
		"cf5cf4a9f57a618709dff5369b17357cbcfa7b165c995ce2c536c86aa78b89fa",
		"8dd2076aa1fc541f23ea6da2123ca565c50783c0ae1c3b064d123cd01c811dac",
	}
	shareInt, _ := big.NewInt(0).SetString(shares[id - 1], 16)
	fmt.Println("FUNC ReadSelfshares :", shareInt)
	return shareInt
}

func GetMainAccountPub() (*ecdsa.PublicKey) {
	Astr := "0x049a0b2c928af39a0dd635702e920864d16ec9846d1517a5e181792d4b84943688746359d46c49045d42b550a27f464919c1838f93d478750deeec48a8a9db12a6"
	accountPub, _ := hexutil.Decode(Astr)
	return crypto.ToECDSAPub(accountPub)
}

func GetSAccountPub() (*ecdsa.PublicKey) {
	Astr := "0x0410286e52cf87851e27a945434700d969ebb4fcd165b1c95edecdde8e4c104938785700797b6579c731f81c9696ba63aea571eca00767175cdb62e3f9284f4a52"
	accountPub, _ := hexutil.Decode(Astr)
	return crypto.ToECDSAPub(accountPub)
}

func GeneratePubFromStr(pubStr string) (*ecdsa.PublicKey) {
	accountPub, _ := hexutil.Decode(pubStr)
	return crypto.ToECDSAPub(accountPub)
}



func CountSubAccountSharePart(sharePriv *big.Int,key *ecdsa.PublicKey)  *ecdsa.PublicKey {
	return multiPub(sharePriv.Bytes(), key)
}

func getPublicKey(data *big.Int) ecdsa.PublicKey{
	priv := generatePrivKey(data)
	pubKey := priv.PublicKey
	fmt.Printf("The pubkey is %x\n", pubKey)
	return pubKey
}

/* shamir private share
 * t_1* b_1 + t_2 * b_2
 * Each share calclate it's own share with b_i, and send to center to calclate pubkey and add it
 */
func TestLibraryCombine1() {
	shares := []string{
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE=Uv8TKu9w935MhVhKudhksXv1QQO_KijTVQ5yCWQNaL4=",
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAI=dwOoQA6zD-kc0KQHm7srZ7sePn_pkOIalCZGbTD1WrI=",
		//"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAM=mwg9VS31KFPtG-_EfZ3yHfpHO_wT95th0z4a0P3dTKY=",
	}

	combined, err := Combine(shares)
	if err != nil {
		fmt.Println("Fatal: combining: ", err)
	}
	fmt.Printf("The combined string: %x\n", combined)

	hexStr := fmt.Sprintf("%x", combined)
	privInt,_ := big.NewInt(0).SetString(hexStr, 16)

	fmt.Printf("%x\n", privInt)

	priv := generatePrivKey(privInt)
	pubKey := priv.PublicKey
	fmt.Println("The pubkey is", pubKey)

	pub:=common.ToHex(crypto.FromECDSAPub(&pubKey))
	fmt.Println(pub)

	return
}


/* shamir private share
 * (t_1* b_1)G + (t_2 * b_2)G
 * Each share calclate it's own share with b_i, and send to center to calclate pubkey and add it
 */
func TestLibraryCombine2() {
	shares := []string{
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE=Uv8TKu9w935MhVhKudhksXv1QQO_KijTVQ5yCWQNaL4=",
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAI=dwOoQA6zD-kc0KQHm7srZ7sePn_pkOIalCZGbTD1WrI=",
		//"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAM=mwg9VS31KFPtG-_EfZ3yHfpHO_wT95th0z4a0P3dTKY=",
	}

	combined, err := CombinePubFirst(shares)
	if err != nil {
		fmt.Println("Fatal: combining: ", err)
	}
	fmt.Printf("The combined string: %x\n", combined)

	hexStr := fmt.Sprintf("%x", combined)
	privInt,_ := big.NewInt(0).SetString(hexStr, 16)

	fmt.Printf("%x\n", privInt)

	priv := generatePrivKey(privInt)
	pubKey := priv.PublicKey
	fmt.Printf("The pubkey is %x\n", pubKey)

	pub:=common.ToHex(crypto.FromECDSAPub(&pubKey))
	fmt.Println(pub)

	return
}

/* shamir private share
 * (t_1 G) * b_1 + (t_2 G) * b_2
 * Each share calclate it's own pubkey share, and send to center to merge all
 */
func TestLibraryCombine3() {
	shares := []string{
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE=Uv8TKu9w935MhVhKudhksXv1QQO_KijTVQ5yCWQNaL4=",
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAI=dwOoQA6zD-kc0KQHm7srZ7sePn_pkOIalCZGbTD1WrI=",
		//"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAM=mwg9VS31KFPtG-_EfZ3yHfpHO_wT95th0z4a0P3dTKY=",
	}

	pubkey1 := getPublicKey(fromBase64(shares[0][44:]))
	pubkey2 := getPublicKey(fromBase64(shares[1][44:]))

	fmt.Println("prikey1", shares[0][44:])
	fmt.Println("prikey2", shares[1][44:])

	str := []string{
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE=" + toBase64(pubkey1.X) + toBase64(pubkey1.Y),
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAI=" + toBase64(pubkey2.X) + toBase64(pubkey2.Y),
	}
	fmt.Println(str)

	combined, err := CombineECDSAPubs(str)
	if err != nil {
		fmt.Println("Fatal: combining: ", err)
	}
	fmt.Printf("The combined string: %x\n", combined)

	hexStr := fmt.Sprintf("%x", combined)
	privInt,_ := big.NewInt(0).SetString(hexStr, 16)

	priv := generatePrivKey(privInt)
	pubKey := priv.PublicKey
	fmt.Printf("The pubkey is %x\n", pubKey)

	pub:=common.ToHex(crypto.FromECDSAPub(&pubKey))
	fmt.Println(pub)

	return
}


/* shamir private share
 * (t_1 A) * b_1 + (t_2 A) * b_2
 * Each share calclate it's own pubkey share, and send to center to merge all
 */
func TestLibraryCombine4() {
	shares := []string{
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE=Uv8TKu9w935MhVhKudhksXv1QQO_KijTVQ5yCWQNaL4=",
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAI=dwOoQA6zD-kc0KQHm7srZ7sePn_pkOIalCZGbTD1WrI=",
		//"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAM=mwg9VS31KFPtG-_EfZ3yHfpHO_wT95th0z4a0P3dTKY=",
	}

	APriv, _ := big.NewInt(0).SetString("e3dc14a49229f85f90c6156ca5fdfcd91e1e131700b60b0eb51cc1662af04713", 16)
	Apub := getPublicKey(APriv)

	fmt.Println("Apub:", Apub)

	sharePub1 := new(ecdsa.PublicKey)
	sharePub1.Curve = crypto.S256()
	sharePub1.X, sharePub1.Y = crypto.S256().ScalarMult(Apub.X, Apub.Y, fromBase64(shares[0][44:]).Bytes())

	sharePub2 := new(ecdsa.PublicKey)
	sharePub2.Curve = crypto.S256()
	sharePub2.X, sharePub2.Y = crypto.S256().ScalarMult(Apub.X, Apub.Y, fromBase64(shares[1][44:]).Bytes())

	str := []string{
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE=" + toBase64(sharePub1.X) + toBase64(sharePub1.Y),
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAI=" + toBase64(sharePub2.X) + toBase64(sharePub2.Y),
	}
	fmt.Println(str)

	combined, err := CombineECDSAPubs(str)
	if err != nil {
		fmt.Println("Fatal: combining: ", err)
	}
	fmt.Printf("The combined string: %x\n", combined)


	bA := crypto.ToECDSAPub([]byte(combined))

	a1s1 := "0263066721be0b345c6f6717f9c4ce9c13acab2012882f70c5a43935cbcf8045cd03a94e9653042091c7bec1b24630aa955bb50bc80ededdd7fb0d2c0f40aeadd8a9"
	sbyte,_:=hexutil.Decode("0x" + a1s1)
	A1, S1, err := keystore.GeneratePKPairFromABaddress(sbyte[:])
	if err !=nil {
		fmt.Println("A1S1 decode failed!", err)
		return
	}

	fmt.Println(crypto.ScanPubSharesA1(bA, S1))
	fmt.Println(A1)

	return
}



