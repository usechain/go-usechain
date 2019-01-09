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
	"strings"
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
	generatedA1, generatedS, s, err := GenerateABKey2528(pa, pb, AprivKey)

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

// GenerateABKey2528 generates an OTA account for receiver using receiver's publickey
func GenerateABKey2528(A *ecdsa.PublicKey, B *ecdsa.PublicKey, AprivKey *ecdsa.PrivateKey) (A1 *ecdsa.PublicKey, S *ecdsa.PublicKey, s *ecdsa.PrivateKey, err error) {
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
	retPriv1, retPriv2, err = GenerateABPrivateKey2528(privateKey, privateKey2, retPub, pb)
	return
}

func GenerateABPrivateKey2528(privateKey *ecdsa.PrivateKey, privateKey2 *ecdsa.PrivateKey, destPubA *ecdsa.PublicKey, destPubB *ecdsa.PublicKey) (retPriv1 *ecdsa.PrivateKey, retPriv2 *ecdsa.PrivateKey, err error) {
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

var one = new(big.Int).SetInt64(1)

// randFieldElement2528 returns a random element of the field
func randFieldElement2528(rand io.Reader) (k *big.Int, err error) {
	params := S256().Params()
	b := make([]byte, params.BitSize/8+8)
	_, err = io.ReadFull(rand, b)
	if err != nil {
		return
	}
	k = new(big.Int).SetBytes(b)
	n := new(big.Int).Sub(params.N, one)
	k.Mod(k, n)
	k.Add(k, one)

	return
}

// calc [x]Hash(P)   KeyImage
func xScalarHashP(x []byte, pub *ecdsa.PublicKey) (I *ecdsa.PublicKey) {
	KeyImg := new(ecdsa.PublicKey)
	I = new(ecdsa.PublicKey)
	KeyImg.X, KeyImg.Y = S256().ScalarMult(pub.X, pub.Y, Keccak256(FromECDSAPub(pub))) //Hash(P)
	I.X, I.Y = S256().ScalarMult(KeyImg.X, KeyImg.Y, x)
	I.Curve = S256()
	return
}

var (
	ErrInvalidRingSignParams = errors.New("invalid ring sign params")
	ErrRingSignFail          = errors.New("ring sign fail")
)

// RingSign is the function of ring signature
func RingSign(M []byte, x *big.Int, PublicKeys []*ecdsa.PublicKey) ([]*ecdsa.PublicKey, *ecdsa.PublicKey, []*big.Int, []*big.Int, error) {
	if M == nil || x == nil || len(PublicKeys) == 0 {
		return nil, nil, nil, nil, ErrInvalidRingSignParams
	}

	for _, publicKey := range PublicKeys {
		if publicKey == nil || publicKey.X == nil || publicKey.Y == nil {
			return nil, nil, nil, nil, ErrInvalidRingSignParams
		}
	}

	n := len(PublicKeys)
	I := xScalarHashP(x.Bytes(), PublicKeys[0]) //Key Image
	if I == nil || I.X == nil || I.Y == nil {
		return nil, nil, nil, nil, ErrRingSignFail
	}

	rnd, rnderr := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if rnderr != nil {
		return nil, nil, nil, nil, ErrRingSignFail
	}
	s := int(rnd.Int64()) //s is the random position for real key

	if s > 0 {
		PublicKeys[0], PublicKeys[s] = PublicKeys[s], PublicKeys[0] //exchange real public key position
	}

	var (
		q = make([]*big.Int, n)
		w = make([]*big.Int, n)
	)

	SumC := new(big.Int).SetInt64(0)
	Lpub := new(ecdsa.PublicKey)
	d := sha3.NewKeccak256()
	d.Write(M)

	var err error
	for i := 0; i < n; i++ {
		q[i], err = randFieldElement2528(rand.Reader)
		if err != nil {
			return nil, nil, nil, nil, err
		}

		w[i], err = randFieldElement2528(rand.Reader)
		if err != nil {
			return nil, nil, nil, nil, err
		}

		Lpub.X, Lpub.Y = S256().ScalarBaseMult(q[i].Bytes()) //[qi]G
		if Lpub.X == nil || Lpub.Y == nil {
			return nil, nil, nil, nil, ErrRingSignFail
		}

		if i != s {
			Ppub := new(ecdsa.PublicKey)
			Ppub.X, Ppub.Y = S256().ScalarMult(PublicKeys[i].X, PublicKeys[i].Y, w[i].Bytes()) //[wi]Pi
			if Ppub.X == nil || Ppub.Y == nil {
				return nil, nil, nil, nil, ErrRingSignFail
			}

			Lpub.X, Lpub.Y = S256().Add(Lpub.X, Lpub.Y, Ppub.X, Ppub.Y) //[qi]G+[wi]Pi

			SumC.Add(SumC, w[i])
			SumC.Mod(SumC, secp256k1_N)
		}

		d.Write(FromECDSAPub(Lpub))
	}

	Rpub := new(ecdsa.PublicKey)
	for i := 0; i < n; i++ {
		Rpub = xScalarHashP(q[i].Bytes(), PublicKeys[i]) //[qi]HashPi
		if Rpub == nil || Rpub.X == nil || Rpub.Y == nil {
			return nil, nil, nil, nil, ErrRingSignFail
		}

		if i != s {
			Ppub := new(ecdsa.PublicKey)
			Ppub.X, Ppub.Y = S256().ScalarMult(I.X, I.Y, w[i].Bytes()) //[wi]I
			if Ppub.X == nil || Ppub.Y == nil {
				return nil, nil, nil, nil, ErrRingSignFail
			}

			Rpub.X, Rpub.Y = S256().Add(Rpub.X, Rpub.Y, Ppub.X, Ppub.Y) //[qi]HashPi+[wi]I
		}

		d.Write(FromECDSAPub(Rpub))
	}

	Cs := new(big.Int).SetBytes(d.Sum(nil)) //hash(m,Li,Ri)
	Cs.Sub(Cs, SumC)
	Cs.Mod(Cs, secp256k1_N)

	tmp := new(big.Int).Mul(Cs, x)
	Rs := new(big.Int).Sub(q[s], tmp)
	Rs.Mod(Rs, secp256k1_N)
	w[s] = Cs
	q[s] = Rs

	return PublicKeys, I, w, q, nil
}

// RingSignedData represents a ring-signed digital signature
type RingSignedData struct {
	PublicKeys []*ecdsa.PublicKey
	KeyImage   *ecdsa.PublicKey
	Ws         []*big.Int
	Qs         []*big.Int
}

var (
	ErrInvalidPrivateKey   = errors.New("invalid private key")
	ErrInvalidPunlicKeySet = errors.New("invalid public key set")
)

// GenRingSignData generate ring sign data
func GenRingSignData(hashMsg string, privateKey string, publickeyset string) (string, string, error) {
	if !hexutil.Has0xPrefix(privateKey) {
		return "", "", ErrInvalidPrivateKey
	}

	hmsg, err := hexutil.Decode(hashMsg)
	if err != nil {
		return "", "", err
	}

	ecdsaPrivateKey, err := HexToECDSA(privateKey[2:])
	if err != nil {
		return "", "", err
	}

	privKey, err := hexutil.Decode(privateKey)
	if err != nil {
		return "", "", err
	}

	if privKey == nil {
		return "", "", ErrInvalidPrivateKey
	}

	publickeys := strings.Split(publickeyset, ",")
	if len(publickeys) == 0 || len(publickeys) > 6 {
		return "", "", ErrInvalidPunlicKeySet
	}

	return genRingSignData(hmsg, privKey, &ecdsaPrivateKey.PublicKey, publickeys)
}

func genRingSignData(hashMsg []byte, privateKey []byte, actualPub *ecdsa.PublicKey, publickeyset []string) (string, string, error) {
	otaPrivD := new(big.Int).SetBytes(privateKey)

	publicKeys := make([]*ecdsa.PublicKey, 0)
	publicKeys = append(publicKeys, actualPub)

	for _, publickey := range publickeyset {
		pubBytes, err := hexutil.Decode(publickey)
		if err != nil {
			return "", "", errors.New("fail to decode publickey!")
		}

		publicKeyA := ToECDSAPub(pubBytes)

		publicKeys = append(publicKeys, publicKeyA)
	}

	retPublicKeys, keyImage, w_random, q_random, err := RingSign(hashMsg, otaPrivD, publicKeys)
	if err != nil {
		return "", "", err
	}

	return encodeRingSignOut(retPublicKeys, keyImage, w_random, q_random) // 这里的key随机调整过位置
}

//  encodeRingSignOut encode all ring sign out data to a string
func encodeRingSignOut(publicKeys []*ecdsa.PublicKey, keyimage *ecdsa.PublicKey, Ws []*big.Int, Qs []*big.Int) (string, string, error) {
	tmp := make([]string, 0)
	for _, pk := range publicKeys {
		tmp = append(tmp, common.ToHex(FromECDSAPub(pk)))
	}

	pkStr := strings.Join(tmp, "&")

	k := common.ToHex(FromECDSAPub(keyimage))

	wa := make([]string, 0)
	for _, wi := range Ws {
		wa = append(wa, hexutil.EncodeBig(wi))
	}
	wStr := strings.Join(wa, "&")

	qa := make([]string, 0)
	for _, qi := range Qs {
		qa = append(qa, hexutil.EncodeBig(qi))
	}
	qStr := strings.Join(qa, "&")

	outs := strings.Join([]string{pkStr, k, wStr, qStr}, "+")
	return outs, k, nil
}

var (
	// invalid ring signed info
	ErrInvalidRingSigned = errors.New("invalid ring signed info")
)

// DecodeRingSignOut decode ringsig string
func DecodeRingSignOut(s string) (error, []*ecdsa.PublicKey, *ecdsa.PublicKey, []*big.Int, []*big.Int) {
	ss := strings.Split(s, "+")
	if len(ss) < 4 {
		return ErrInvalidRingSigned, nil, nil, nil, nil
	}

	ps := ss[0]
	k := ss[1]
	ws := ss[2]
	qs := ss[3]

	pa := strings.Split(ps, "&")
	publickeys := make([]*ecdsa.PublicKey, 0)
	for _, pi := range pa {

		publickey := ToECDSAPub(common.FromHex(pi))
		if publickey == nil || publickey.X == nil || publickey.Y == nil {
			return ErrInvalidRingSigned, nil, nil, nil, nil
		}

		publickeys = append(publickeys, publickey)
	}

	keyimgae := ToECDSAPub(common.FromHex(k))
	if keyimgae == nil || keyimgae.X == nil || keyimgae.Y == nil {
		return ErrInvalidRingSigned, nil, nil, nil, nil
	}

	wa := strings.Split(ws, "&")
	w := make([]*big.Int, 0)
	for _, wi := range wa {
		bi, err := hexutil.DecodeBig(wi)
		if bi == nil || err != nil {
			return ErrInvalidRingSigned, nil, nil, nil, nil
		}

		w = append(w, bi)
	}

	qa := strings.Split(qs, "&")
	q := make([]*big.Int, 0)
	for _, qi := range qa {
		bi, err := hexutil.DecodeBig(qi)
		if bi == nil || err != nil {
			return ErrInvalidRingSigned, nil, nil, nil, nil
		}

		q = append(q, bi)
	}

	if len(publickeys) != len(w) || len(publickeys) != len(q) {
		return ErrInvalidRingSigned, nil, nil, nil, nil
	}

	return nil, publickeys, keyimgae, w, q
}

// VerifyRingSign verifies the validity of ring signature
func verifyRingSign(M []byte, PublicKeys []*ecdsa.PublicKey, I *ecdsa.PublicKey, c []*big.Int, r []*big.Int) bool {
	if M == nil || PublicKeys == nil || I == nil || c == nil || r == nil {
		return false
	}

	if len(PublicKeys) == 0 || len(PublicKeys) != len(c) || len(PublicKeys) != len(r) {
		return false
	}

	n := len(PublicKeys)
	for i := 0; i < n; i++ {
		if PublicKeys[i] == nil || PublicKeys[i].X == nil || PublicKeys[i].Y == nil ||
			c[i] == nil || r[i] == nil {
			return false
		}
	}

	log.Debug("M info", "R", 0, "M", common.ToHex(M))
	for i := 0; i < n; i++ {
		log.Debug("publicKeys", "i", i, "publickey", common.ToHex(FromECDSAPub(PublicKeys[i])))
	}

	log.Debug("image info", "I", common.ToHex(FromECDSAPub(I)))
	for i := 0; i < n; i++ {
		log.Debug("c info", "i", i, "c", common.ToHex(c[i].Bytes()))
	}

	for i := 0; i < n; i++ {
		log.Debug("r info", "i", i, "r", common.ToHex(r[i].Bytes()))
	}

	SumC := new(big.Int).SetInt64(0)
	Lpub := new(ecdsa.PublicKey)
	d := sha3.NewKeccak256()
	d.Write(M)

	//hash(M,Li,Ri)
	for i := 0; i < n; i++ {
		Lpub.X, Lpub.Y = S256().ScalarBaseMult(r[i].Bytes()) //[ri]G
		if Lpub.X == nil || Lpub.Y == nil {
			return false
		}

		Ppub := new(ecdsa.PublicKey)
		Ppub.X, Ppub.Y = S256().ScalarMult(PublicKeys[i].X, PublicKeys[i].Y, c[i].Bytes()) //[ci]Pi
		if Ppub.X == nil || Ppub.Y == nil {
			return false
		}

		Lpub.X, Lpub.Y = S256().Add(Lpub.X, Lpub.Y, Ppub.X, Ppub.Y) //[ri]G+[ci]Pi
		SumC.Add(SumC, c[i])
		SumC.Mod(SumC, secp256k1_N)
		d.Write(FromECDSAPub(Lpub))
		log.Debug("LPublicKeys", "i", i, "Lpub", common.ToHex(FromECDSAPub(Lpub)))
	}

	Rpub := new(ecdsa.PublicKey)
	for i := 0; i < n; i++ {
		Rpub = xScalarHashP(r[i].Bytes(), PublicKeys[i]) //[qi]HashPi
		if Rpub == nil || Rpub.X == nil || Rpub.Y == nil {
			return false
		}

		Ppub := new(ecdsa.PublicKey)
		Ppub.X, Ppub.Y = S256().ScalarMult(I.X, I.Y, c[i].Bytes()) //[wi]I
		if Ppub.X == nil || Ppub.Y == nil {
			return false
		}

		Rpub.X, Rpub.Y = S256().Add(Rpub.X, Rpub.Y, Ppub.X, Ppub.Y) //[qi]HashPi+[wi]I
		log.Debug("RPublicKeys", "i", i, "Rpub", common.ToHex(FromECDSAPub(Rpub)))

		d.Write(FromECDSAPub(Rpub))
	}

	hash := new(big.Int).SetBytes(d.Sum(nil)) //hash(m,Li,Ri)
	log.Debug("hash info", "i", 0, "hash", common.ToHex(hash.Bytes()))

	hash.Mod(hash, secp256k1_N)
	log.Debug("hash info", "i", 2, "hash", common.ToHex(hash.Bytes()))
	log.Debug("SumC info", "i", 3, "SumC", common.ToHex(SumC.Bytes()))

	return hash.Cmp(SumC) == 0
}

// VerifyRingSign verify ring signature
func VerifyRingSign(msg string, ringsig string) bool {

	msg1, err := hexutil.Decode(msg)
	if err != nil {
		log.Error("VerifyRingSign decode msg error")
		return false
	}
	msg2 := Keccak256(msg1)

	err, publickeys, keyimage, c, r := DecodeRingSignOut(ringsig)
	if err != nil {
		return false
	}

	verifyRES := verifyRingSign(msg2, publickeys, keyimage, c, r)
	return verifyRES
}
