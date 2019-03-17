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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"os"

	"github.com/usechain/go-usechain/common"
	"github.com/usechain/go-usechain/common/hexutil"
	"github.com/usechain/go-usechain/common/math"
	"github.com/usechain/go-usechain/crypto/sha3"
	"github.com/usechain/go-usechain/log"
	"github.com/usechain/go-usechain/rlp"
)

var (
	secp256k1_N, _  = new(big.Int).SetString("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)
	secp256k1_halfN = new(big.Int).Div(secp256k1_N, big.NewInt(2))
)

// Keccak256 calculates and returns the Keccak256 hash of the input data.
func Keccak256(data ...[]byte) []byte {
	d := sha3.NewKeccak256()
	for _, b := range data {
		d.Write(b)
	}
	return d.Sum(nil)
}

// Keccak256Hash calculates and returns the Keccak256 hash of the input data,
// converting it to an internal Hash data structure.
func Keccak256Hash(data ...[]byte) (h common.Hash) {
	d := sha3.NewKeccak256()
	for _, b := range data {
		d.Write(b)
	}
	d.Sum(h[:0])
	return h
}

// Keccak512 calculates and returns the Keccak512 hash of the input data.
func Keccak512(data ...[]byte) []byte {
	d := sha3.NewKeccak512()
	for _, b := range data {
		d.Write(b)
	}
	return d.Sum(nil)
}

// Creates an ethereum address given the bytes and the nonce
func CreateAddress(b common.Address, nonce uint64) common.Address {
	data, _ := rlp.EncodeToBytes([]interface{}{b, nonce})
	return common.BytesToAddress(Keccak256(data)[12:])
}

// ToECDSA creates a private key with the given D value.
func ToECDSA(d []byte) (*ecdsa.PrivateKey, error) {
	return toECDSA(d, true)
}

// ToECDSAUnsafe blindly converts a binary blob to a private key. It should almost
// never be used unless you are sure the input is valid and want to avoid hitting
// errors due to bad origin encoding (0 prefixes cut off).
func ToECDSAUnsafe(d []byte) *ecdsa.PrivateKey {
	priv, _ := toECDSA(d, false)
	return priv
}

// toECDSA creates a private key with the given D value. The strict parameter
// controls whether the key's length should be enforced at the curve size or
// it can also accept legacy encodings (0 prefixes).
func toECDSA(d []byte, strict bool) (*ecdsa.PrivateKey, error) {
	priv := new(ecdsa.PrivateKey)
	priv.PublicKey.Curve = S256()
	if strict && 8*len(d) != priv.Params().BitSize {
		return nil, fmt.Errorf("invalid length, need %d bits", priv.Params().BitSize)
	}
	priv.D = new(big.Int).SetBytes(d)

	// The priv.D must < N
	if priv.D.Cmp(secp256k1_N) >= 0 {
		return nil, fmt.Errorf("invalid private key, >=N")
	}
	// The priv.D must not be zero or negative.
	if priv.D.Sign() <= 0 {
		return nil, fmt.Errorf("invalid private key, zero or negative")
	}

	priv.PublicKey.X, priv.PublicKey.Y = priv.PublicKey.Curve.ScalarBaseMult(d)
	if priv.PublicKey.X == nil {
		return nil, errors.New("invalid private key")
	}
	return priv, nil
}

// FromECDSA exports a private key into a binary dump.
func FromECDSA(priv *ecdsa.PrivateKey) []byte {
	if priv == nil {
		return nil
	}
	return math.PaddedBigBytes(priv.D, priv.Params().BitSize/8)
}

func ToECDSAPub(pub []byte) *ecdsa.PublicKey {
	if len(pub) == 0 {
		return nil
	}
	x, y := elliptic.Unmarshal(S256(), pub)
	return &ecdsa.PublicKey{Curve: S256(), X: x, Y: y}
}

func FromECDSAPub(pub *ecdsa.PublicKey) []byte {
	if pub == nil || pub.X == nil || pub.Y == nil {
		return nil
	}
	return elliptic.Marshal(S256(), pub.X, pub.Y)
}

// HexToECDSA parses a secp256k1 private key.
func HexToECDSA(hexkey string) (*ecdsa.PrivateKey, error) {
	b, err := hex.DecodeString(hexkey)
	if err != nil {
		return nil, errors.New("invalid hex string")
	}
	return ToECDSA(b)
}

// LoadECDSA loads a secp256k1 private key from the given file.
func LoadECDSA(file string) (*ecdsa.PrivateKey, error) {
	buf := make([]byte, 64)
	fd, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer fd.Close()
	if _, err := io.ReadFull(fd, buf); err != nil {
		return nil, err
	}

	key, err := hex.DecodeString(string(buf))
	if err != nil {
		return nil, err
	}
	return ToECDSA(key)
}

// SaveECDSA saves a secp256k1 private key to the given file with
// restrictive permissions. The key data is saved hex-encoded.
func SaveECDSA(file string, key *ecdsa.PrivateKey) error {
	k := hex.EncodeToString(FromECDSA(key))
	return ioutil.WriteFile(file, []byte(k), 0600)
}

func GenerateKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(S256(), rand.Reader)
}

// ValidateSignatureValues verifies whether the signature values are valid with
// the given chain rules. The v value is assumed to be either 0 or 1.
func ValidateSignatureValues(v byte, r, s *big.Int, homestead bool) bool {
	if r.Cmp(common.Big1) < 0 || s.Cmp(common.Big1) < 0 {
		return false
	}
	// reject upper range of s values (ECDSA malleability)
	// see discussion in secp256k1/libsecp256k1/include/secp256k1.h
	if homestead && s.Cmp(secp256k1_halfN) > 0 {
		return false
	}
	// Frontier: allow s to be in full N range
	return r.Cmp(secp256k1_N) < 0 && s.Cmp(secp256k1_N) < 0 && (v == 0 || v == 1)
}

// VerifySig recover the pubkey from signature
// And verifies whether the signature values are valid
func VerifySig(sig []byte, hash common.Hash) bool {
	pub, err := Ecrecover(hash.Bytes(), sig)
	if err != nil {
		log.Error("retrieve public key failed")
		return false
	}
	return VerifySignature(pub, hash.Bytes(), sig[:64])
}

func PubkeyToAddress(p ecdsa.PublicKey) common.Address {
	pubBytes := FromECDSAPub(&p)
	return common.BytesToAddress(Keccak256(pubBytes[1:])[12:])
}

func zeroBytes(bytes []byte) {
	for i := range bytes {
		bytes[i] = 0
	}
}

// Generate account interface
func GenerateABKey(AX string, AY string, BX string, BY string, AprivKey *ecdsa.PrivateKey) (ret []string, s *ecdsa.PrivateKey, err error) {
	bytesAX, err := hexutil.Decode(AX)
	if err != nil {
		return
	}
	bytesAY, err := hexutil.Decode(AY)
	if err != nil {
		return
	}
	bytesBX, err := hexutil.Decode(BX)
	if err != nil {
		return
	}
	bytesBY, err := hexutil.Decode(BY)
	if err != nil {
		return
	}
	bnAX := new(big.Int).SetBytes(bytesAX)
	bnAY := new(big.Int).SetBytes(bytesAY)
	bnBX := new(big.Int).SetBytes(bytesBX)
	bnBY := new(big.Int).SetBytes(bytesBY)

	pa := &ecdsa.PublicKey{X: bnAX, Y: bnAY}
	pb := &ecdsa.PublicKey{X: bnBX, Y: bnBY}
	generatedA1, generatedS, s, err := GenerateABPrivKey(pa, pb, AprivKey)

	A1 := common.ToHex(FromECDSAPub(generatedA1))
	SS := common.ToHex(FromECDSAPub(generatedS))
	//ss:=hexutil.Encode(s.D.Bytes())
	log.Info("newABaccount infomation", "A1", A1)
	log.Info("newABaccount infomation", "S", SS)
	//fmt.Println("newABaccount infomation","A1",ss)

	return hexutil.PKPair2HexSlice(generatedA1, generatedS), s, nil
}

// A1=[hash([b]A)]G+S
func GenerateSubAccount(bA *ecdsa.PublicKey, S *ecdsa.PublicKey) common.Address {
	hashBytes := Keccak256(FromECDSAPub(bA)) //hash([b]A)
	A1 := new(ecdsa.PublicKey)
	A1.Curve = S256()
	A1.X, A1.Y = S256().ScalarBaseMult(hashBytes) //[hash([b]A)]G
	A1.X, A1.Y = S256().Add(A1.X, A1.Y, S.X, S.Y)

	return PubkeyToAddress(*A1)
}

// GenerateABPrivKey generates an OTA account for receiver using receiver's publickey
func GenerateABPrivKey(A *ecdsa.PublicKey, B *ecdsa.PublicKey, AprivKey *ecdsa.PrivateKey) (A1 *ecdsa.PublicKey, S *ecdsa.PublicKey, s *ecdsa.PrivateKey, err error) {
	s, err = GenerateKey()
	if err != nil {
		return nil, nil, nil, err
	}
	S = &s.PublicKey
	A1 = new(ecdsa.PublicKey)
	*A1 = generateA1(S, B, AprivKey)
	return A1, S, s, err
}

// A1=[hash([b]A)]G+S
func ScanA1(b []byte, A *ecdsa.PublicKey, S *ecdsa.PublicKey) ecdsa.PublicKey {
	bPriv, _ := toECDSA(b, true)
	return generateA1(S, A, bPriv)
}

// A1=[hash([b]A)]G+S
func ScanPubSharesA1(bA *ecdsa.PublicKey, S *ecdsa.PublicKey) ecdsa.PublicKey {
	A1 := new(ecdsa.PublicKey)

	A1.X = bA.X
	A1.Y = bA.Y

	A1Bytes := Keccak256(FromECDSAPub(A1)) //hash([a]B)

	A1.X, A1.Y = S256().ScalarBaseMult(A1Bytes) //[hash([a]B)]G

	A1.X, A1.Y = S256().Add(A1.X, A1.Y, S.X, S.Y) //A1=[hash([a]B)]G+S
	A1.Curve = S256()
	return *A1
}

// generateA1 generate one pulic key of AB account by using algorithm A1=[hash([a]B)]G+S
func generateA1(S *ecdsa.PublicKey, B *ecdsa.PublicKey, AprivKey *ecdsa.PrivateKey) ecdsa.PublicKey {
	A1 := new(ecdsa.PublicKey)

	A1.X, A1.Y = S256().ScalarMult(B.X, B.Y, AprivKey.D.Bytes()) //A1=[a]B

	A1Bytes := Keccak256(FromECDSAPub(A1)) //hash([a]B)

	A1.X, A1.Y = S256().ScalarBaseMult(A1Bytes) //[hash([a]B)]G

	A1.X, A1.Y = S256().Add(A1.X, A1.Y, S.X, S.Y) //A1=[hash([a]B)]G+S
	A1.Curve = S256()
	return *A1
}

func GenerateCreditPubKey(committeepubkey string, privkey *ecdsa.PrivateKey) *ecdsa.PublicKey {
	ecdsaPub := ToECDSAPub(common.FromHex(committeepubkey))

	A := new(ecdsa.PublicKey)

	A.X, A.Y = S256().ScalarMult(ecdsaPub.X, ecdsaPub.Y, privkey.D.Bytes()) // A = [a]B
	ABytes := Keccak256(FromECDSAPub(A))                                    // hash([a]B)
	A.X, A.Y = S256().ScalarBaseMult(ABytes)                                // A = [hash([a]B)]G
	A.Curve = S256()
	return A
}

func GenerateCreditPrivKey(bigint string, pubkey *ecdsa.PublicKey) *ecdsa.PrivateKey {
	// priv, _ := HexToECDSA(committeeprivkey)
	A := new(ecdsa.PublicKey)
	n := new(big.Int)

	n, _ = n.SetString(bigint, 10)
	A.X, A.Y = S256().ScalarMult(pubkey.X, pubkey.Y, n.Bytes()) // [A]b
	ABytes := Keccak256(FromECDSAPub(A))                        // hash([A]b)
	B, _ := ToECDSA(ABytes)
	return B
}

// GenerteABPrivateKey generates the privatekey for an AB account using receiver's main account's privatekey
func GenerteABPrivateKey(privateKey *ecdsa.PrivateKey, privateKey2 *ecdsa.PrivateKey, AX string, AY string, BX string, BY string) (retPub *ecdsa.PublicKey, retPriv1 *ecdsa.PrivateKey, retPriv2 *ecdsa.PrivateKey, err error) {
	bytesAX, err := hexutil.Decode(AX)
	if err != nil {
		return
	}
	bytesAY, err := hexutil.Decode(AY)
	if err != nil {
		return
	}
	bytesBX, err := hexutil.Decode(BX)
	if err != nil {
		return
	}
	bytesBY, err := hexutil.Decode(BY)
	if err != nil {
		return
	}
	bnAX := new(big.Int).SetBytes(bytesAX)
	bnAY := new(big.Int).SetBytes(bytesAY)
	bnBX := new(big.Int).SetBytes(bytesBX)
	bnBY := new(big.Int).SetBytes(bytesBY)

	retPub = &ecdsa.PublicKey{X: bnAX, Y: bnAY}
	pb := &ecdsa.PublicKey{X: bnBX, Y: bnBY}
	retPriv1, retPriv2, err = GenerateABPrivateKey(privateKey, privateKey2, retPub, pb)
	return
}

func GenerateABPrivateKey(privateKey *ecdsa.PrivateKey, privateKey2 *ecdsa.PrivateKey, destPubA *ecdsa.PublicKey, destPubB *ecdsa.PublicKey) (retPriv1 *ecdsa.PrivateKey, retPriv2 *ecdsa.PrivateKey, err error) {
	pub := new(ecdsa.PublicKey)
	pub.X, pub.Y = S256().ScalarMult(destPubB.X, destPubB.Y, privateKey.D.Bytes()) //[a]B

	//hash
	k := new(big.Int).SetBytes(Keccak256(FromECDSAPub(pub))) //hash([a]B)

	k.Add(k, privateKey2.D)     //hash([a]B)+s
	k.Mod(k, S256().Params().N) //mod to feild N

	retPriv1 = new(ecdsa.PrivateKey)
	retPriv2 = new(ecdsa.PrivateKey)

	retPriv1.D = k
	retPriv2.D = new(big.Int).SetInt64(0)

	return retPriv1, retPriv2, nil
}
