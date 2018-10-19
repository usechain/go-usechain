// Copyright 2014 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package crypto

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/hex"
	"io/ioutil"
	"math/big"
	"os"
	"testing"

	"github.com/usechain/go-usechain/common"
	"github.com/usechain/go-usechain/common/hexutil"
)

var testAddrHex = "970e8128ab834e8eac17ab8e3812f010678cf791"
var testPrivHex = "289c2857d4598e37fb9647507e47a309d6133539bf21a8b9cb6df88fd5232032"

// These tests are sanity checks.
// They should ensure that we don't e.g. use Sha3-224 instead of Sha3-256
// and that the sha3 library uses keccak-f permutation.
func TestKeccak256Hash(t *testing.T) {
	msg := []byte("abc")
	exp, _ := hex.DecodeString("4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45")
	checkhash(t, "Sha3-256-array", func(in []byte) []byte { h := Keccak256Hash(in); return h[:] }, msg, exp)
}

func TestToECDSAErrors(t *testing.T) {
	if _, err := HexToECDSA("0000000000000000000000000000000000000000000000000000000000000000"); err == nil {
		t.Fatal("HexToECDSA should've returned error")
	}
	if _, err := HexToECDSA("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); err == nil {
		t.Fatal("HexToECDSA should've returned error")
	}
}

func BenchmarkSha3(b *testing.B) {
	a := []byte("hello world")
	for i := 0; i < b.N; i++ {
		Keccak256(a)
	}
}

func TestSign(t *testing.T) {
	key, _ := HexToECDSA(testPrivHex)
	addr := common.HexToAddress(testAddrHex)

	msg := Keccak256([]byte("foo"))
	sig, err := Sign(msg, key)
	if err != nil {
		t.Errorf("Sign error: %s", err)
	}
	recoveredPub, err := Ecrecover(msg, sig)
	if err != nil {
		t.Errorf("ECRecover error: %s", err)
	}
	pubKey := ToECDSAPub(recoveredPub)
	recoveredAddr := PubkeyToAddress(*pubKey)
	if addr != recoveredAddr {
		t.Errorf("Address mismatch: want: %x have: %x", addr, recoveredAddr)
	}

	// should be equal to SigToPub
	recoveredPub2, err := SigToPub(msg, sig)
	if err != nil {
		t.Errorf("ECRecover error: %s", err)
	}
	recoveredAddr2 := PubkeyToAddress(*recoveredPub2)
	if addr != recoveredAddr2 {
		t.Errorf("Address mismatch: want: %x have: %x", addr, recoveredAddr2)
	}
}

func TestInvalidSign(t *testing.T) {
	if _, err := Sign(make([]byte, 1), nil); err == nil {
		t.Errorf("expected sign with hash 1 byte to error")
	}
	if _, err := Sign(make([]byte, 33), nil); err == nil {
		t.Errorf("expected sign with hash 33 byte to error")
	}
}

func TestNewContractAddress(t *testing.T) {
	key, _ := HexToECDSA(testPrivHex)
	addr := common.HexToAddress(testAddrHex)
	genAddr := PubkeyToAddress(key.PublicKey)
	// sanity check before using addr to create contract address
	checkAddr(t, genAddr, addr)

	caddr0 := CreateAddress(addr, 0)
	caddr1 := CreateAddress(addr, 1)
	caddr2 := CreateAddress(addr, 2)
	checkAddr(t, common.HexToAddress("333c3310824b7c685133f2bedb2ca4b8b4df633d"), caddr0)
	checkAddr(t, common.HexToAddress("8bda78331c916a08481428e4b07c96d3e916d165"), caddr1)
	checkAddr(t, common.HexToAddress("c9ddedf451bc62ce88bf9292afb13df35b670699"), caddr2)
}

func TestLoadECDSAFile(t *testing.T) {
	keyBytes := common.FromHex(testPrivHex)
	fileName0 := "test_key0"
	fileName1 := "test_key1"
	checkKey := func(k *ecdsa.PrivateKey) {
		checkAddr(t, PubkeyToAddress(k.PublicKey), common.HexToAddress(testAddrHex))
		loadedKeyBytes := FromECDSA(k)
		if !bytes.Equal(loadedKeyBytes, keyBytes) {
			t.Fatalf("private key mismatch: want: %x have: %x", keyBytes, loadedKeyBytes)
		}
	}

	ioutil.WriteFile(fileName0, []byte(testPrivHex), 0600)
	defer os.Remove(fileName0)

	key0, err := LoadECDSA(fileName0)
	if err != nil {
		t.Fatal(err)
	}
	checkKey(key0)

	// again, this time with SaveECDSA instead of manual save:
	err = SaveECDSA(fileName1, key0)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(fileName1)

	key1, err := LoadECDSA(fileName1)
	if err != nil {
		t.Fatal(err)
	}
	checkKey(key1)
}

func TestValidateSignatureValues(t *testing.T) {
	check := func(expected bool, v byte, r, s *big.Int) {
		if ValidateSignatureValues(v, r, s, false) != expected {
			t.Errorf("mismatch for v: %d r: %d s: %d want: %v", v, r, s, expected)
		}
	}
	minusOne := big.NewInt(-1)
	one := common.Big1
	zero := common.Big0
	secp256k1nMinus1 := new(big.Int).Sub(secp256k1_N, common.Big1)

	// correct v,r,s
	check(true, 0, one, one)
	check(true, 1, one, one)
	// incorrect v, correct r,s,
	check(false, 2, one, one)
	check(false, 3, one, one)

	// incorrect v, combinations of incorrect/correct r,s at lower limit
	check(false, 2, zero, zero)
	check(false, 2, zero, one)
	check(false, 2, one, zero)
	check(false, 2, one, one)

	// correct v for any combination of incorrect r,s
	check(false, 0, zero, zero)
	check(false, 0, zero, one)
	check(false, 0, one, zero)

	check(false, 1, zero, zero)
	check(false, 1, zero, one)
	check(false, 1, one, zero)

	// correct sig with max r,s
	check(true, 0, secp256k1nMinus1, secp256k1nMinus1)
	// correct v, combinations of incorrect r,s at upper limit
	check(false, 0, secp256k1_N, secp256k1nMinus1)
	check(false, 0, secp256k1nMinus1, secp256k1_N)
	check(false, 0, secp256k1_N, secp256k1_N)

	// current callers ensures r,s cannot be negative, but let's test for that too
	// as crypto package could be used stand-alone
	check(false, 0, minusOne, one)
	check(false, 0, one, minusOne)
}

func checkhash(t *testing.T, name string, f func([]byte) []byte, msg, exp []byte) {
	sum := f(msg)
	if !bytes.Equal(exp, sum) {
		t.Fatalf("hash %s mismatch: want: %x have: %x", name, exp, sum)
	}
}

func checkAddr(t *testing.T, addr0, addr1 common.Address) {
	if addr0 != addr1 {
		t.Fatalf("address mismatch: want: %x have: %x", addr0, addr1)
	}
}

// test to help Python team with integration of libsecp256k1
// skip but keep it after they are done
func TestPythonIntegration(t *testing.T) {
	kh := "289c2857d4598e37fb9647507e47a309d6133539bf21a8b9cb6df88fd5232032"
	k0, _ := HexToECDSA(kh)

	msg0 := Keccak256([]byte("foo"))
	sig0, _ := Sign(msg0, k0)

	msg1 := common.FromHex("00000000000000000000000000000000")
	sig1, _ := Sign(msg0, k0)

	t.Logf("msg: %x, privkey: %s sig: %x\n", msg0, kh, sig0)
	t.Logf("msg: %x, privkey: %s sig: %x\n", msg1, kh, sig1)
}

///////////////////////////greg add 2018/07/04/////////////////////////////
/////////////////////////////////////////////////////////////////////////
func TestRingSign(t *testing.T) {

	address := "0xb24f93396c915E003bd713319366c6fFA281cb9D"
	msg1, _ := hexutil.Decode(address)
	msg := Keccak256(msg1)
	msg2 := hexutil.Encode(msg)

	privateKey := "0x6dc1c88c2362cb85d6468ba225c5c0b39bbb216c9b67ad65e54c0000b00257c5"

	publickeys := "0x04a3781e211cb2ad11e8d98b10eac054969e511faca98e22e68efe72d207314876ed3d53d823b4c74d911619c1854f4a7fce4811d086099a155911ef16a397e6bc," +
		"0x04f80cc382ad254a4a94b15abf0c27af79933fe04cfdda1af8797244ac0c75def559772be355f081bd1ba146643efdb2fa4b538a587f173ef6c3731aec41756455," +
		"0x0418c59aec60da2c04946710781ee839509ad2d3a188dc71710d684a50a25b5d7c648055cae6663ff10cb8e11e1d31e19a99533ad5637affdb61a053d5af6c3fe4," +
		"0x04b00d07ab9d843e1375ea42d13ea8f30f97342795329fe5973281822092cde153f8ab504d25a4887dd67a9e111f5a824ee9eb24ce59c9c3d09d07af2975599a9f," +
		"0x0418c59aec60da2c04946710781ee839509ad2d3a188dc71710d684a50a25b5d7c648055cae6663ff10cb8e11e1d31e19a99533ad5637affdb61a053d5af6c3fe4"
	res, _, err := GenRingSignData(msg2, privateKey, publickeys)
	if err != nil {
		t.Fatal("ringsing error", err)
	}

	verifyRES := VerifyRingSign(address, res)
	if verifyRES != true {
		t.Error("Wrong Ring Signature!")
	}
}

func TestVerifyRingSign(t *testing.T) {
	msg := "0xb24f93396c915E003bd713319366c6fFA281cb9D"
	ringsig := "0x04a3781e211cb2ad11e8d98b10eac054969e511faca98e22e68efe72d207314876ed3d53d823b4c74d911619c1854f4a7fce4811d086099a155911ef16a397e6bc&0x048579ab48414e804dcb328855e954850e6a9c2a7d3e61435938f6fe1f3c7905fc15eb4ace284d21a9764b56cefc61cff3749df86ef31cb71c7bf61f47c5b152a7&0x04f80cc382ad254a4a94b15abf0c27af79933fe04cfdda1af8797244ac0c75def559772be355f081bd1ba146643efdb2fa4b538a587f173ef6c3731aec41756455&0x0418c59aec60da2c04946710781ee839509ad2d3a188dc71710d684a50a25b5d7c648055cae6663ff10cb8e11e1d31e19a99533ad5637affdb61a053d5af6c3fe4&0x04b00d07ab9d843e1375ea42d13ea8f30f97342795329fe5973281822092cde153f8ab504d25a4887dd67a9e111f5a824ee9eb24ce59c9c3d09d07af2975599a9f&0x0418c59aec60da2c04946710781ee839509ad2d3a188dc71710d684a50a25b5d7c648055cae6663ff10cb8e11e1d31e19a99533ad5637affdb61a053d5af6c3fe4+0x0499b7e7aedb55e94580b25843b8829159c12704d3921bddf9c04ea2c77543af2a2449a63b0618d32b1a9db7167aa10a705f75f2082abb153db304ab43d204af77+0x62f4afad6059b78d1d6c5b8a469fc3445f28f5bdd7b0cd7db7a42807d66e68b6&0xc2c75dda6427fd92ea13cda76beff5a562a1db8615eadfc7bc30eef431bc0f13&0x98b14724b0eaa855d8ce815055201fe5672a53c5f40f55d1b7be477b1f0827e3&0x30da249676695ddf70df2be28ac1f75d8339430a51af38f5f7ef790457b17297&0xcd2181296061e9b1daeba5cfa4f574efc52f129d2fe8a9666a69c7a4aeeaa262&0x3d6c828a86549b3d33503633087e38dbc16f91ec7b539311d342a4e7f7250460+0xdca3e364de413de791dc23ab2380ac180c442594df5b6d893213117c7a666b29&0x5643f2ed5975059a79d7a862bb382568640a452fd4781aad6a30e8f765019539&0x6196a4976a9c7164d717abba55caf985632cecd5be7d04691cbffa53122337a8&0x3394b30501572c5b3e38f17d3ddd511b4b801cf55688c3a5f1bbbdf1061de75b&0xb5c5166dbcb8dcb9533b26dc4a4e14a65769f00ba7ad1f8655625a276eed3081&0x658bb92f5be8d0059c2f8f22034aa7ba68d277e9f0cefb2bf2cb317462a2e74a"
	msg1, _ := hexutil.Decode(msg)
	msg2 := Keccak256(msg1)

	err, publickeys, keyimage, c, r := DecodeRingSignOut(ringsig)
	if err != nil {
		t.Fatal("false")
	}

	verifyRES := verifyRingSign(msg2, publickeys, keyimage, c, r)
	if verifyRES != true {
		t.Error("Verify signature return false!")
	}
}
