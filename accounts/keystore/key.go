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

package keystore

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"github.com/pborman/uuid"
	"github.com/usechain/go-usechain/accounts"
	"github.com/usechain/go-usechain/common"
	"github.com/usechain/go-usechain/common/hexutil"
	"github.com/usechain/go-usechain/crypto"
	"github.com/usechain/go-usechain/log"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	version = 3
)

type Key struct {
	Id uuid.UUID // Version 4 "random" for unique id not derived from key data
	// to simplify lookups we also store the address
	Address common.Address
	// we only store privkey as pubkey/address can be derived from it
	// privkey in this struct is always in plaintext
	PrivateKey *ecdsa.PrivateKey

	PrivateKey2 *ecdsa.PrivateKey
	ABaddress   common.ABaddress
}

type keyStore interface {
	// Loads and decrypts the key from disk.
	GetKey(addr common.Address, filename string, auth string) (*Key, error)

	// Loads an encrypted keyfile from disk
	GetEncryptedKey(addr common.Address, filename string) (*Key, error)

	// Writes and encrypts the key.
	StoreKey(filename string, k *Key, auth string) error
	// Joins filename with the key directory unless it is already absolute.
	JoinPath(filename string) string
}

type plainKeyJSON struct {
	Address    string `json:"address"`
	PrivateKey string `json:"privatekey"`
	Id         string `json:"id"`
	Version    int    `json:"version"`
}

type encryptedKeyJSONV3 struct {
	Address   string     `json:"address"`
	Crypto    cryptoJSON `json:"crypto"`
	Id        string     `json:"id"`
	Version   int        `json:"version"`
	ABaddress string     `json:"ABaddress"`
}

type encryptedKeyJSONV1 struct {
	Address string     `json:"address"`
	Crypto  cryptoJSON `json:"crypto"`
	Id      string     `json:"id"`
	Version string     `json:"version"`
}

type cryptoJSON struct {
	Cipher       string                 `json:"cipher"`
	CipherText   string                 `json:"ciphertext"`
	CipherParams cipherparamsJSON       `json:"cipherparams"`
	KDF          string                 `json:"kdf"`
	KDFParams    map[string]interface{} `json:"kdfparams"`
	MAC          string                 `json:"mac"`
}

type cipherparamsJSON struct {
	IV string `json:"iv"`
}

func (k *Key) MarshalJSON() (j []byte, err error) {
	jStruct := plainKeyJSON{
		hex.EncodeToString(k.Address[:]),
		hex.EncodeToString(crypto.FromECDSA(k.PrivateKey)),
		k.Id.String(),
		version,
	}
	j, err = json.Marshal(jStruct)
	return j, err
}

func (k *Key) UnmarshalJSON(j []byte) (err error) {
	keyJSON := new(plainKeyJSON)
	err = json.Unmarshal(j, &keyJSON)
	if err != nil {
		return err
	}

	u := new(uuid.UUID)
	*u = uuid.Parse(keyJSON.Id)
	k.Id = *u
	addr, err := hex.DecodeString(keyJSON.Address)
	if err != nil {
		return err
	}
	privkey, err := crypto.HexToECDSA(keyJSON.PrivateKey)
	if err != nil {
		return err
	}

	k.Address = common.BytesToAddress(addr)
	k.PrivateKey = privkey

	return nil
}

func newKeyFromECDSA(privateKeyECDSA *ecdsa.PrivateKey) *Key {
	id := uuid.NewRandom()
	key := &Key{
		Id:         id,
		Address:    crypto.PubkeyToAddress(privateKeyECDSA.PublicKey),
		PrivateKey: privateKeyECDSA,
	}
	//updateABaddress(key)
	return key
}

// NewKeyForDirectICAP generates a key whose address fits into < 155 bits so it can fit
// into the Direct ICAP spec. for simplicity and easier compatibility with other libs, we
// retry until the first byte is 0.
func NewKeyForDirectICAP(rand io.Reader) *Key {
	randBytes := make([]byte, 64)
	_, err := rand.Read(randBytes)
	if err != nil {
		panic("key generation: could not read from random source: " + err.Error())
	}
	reader := bytes.NewReader(randBytes)
	privateKeyECDSA, err := ecdsa.GenerateKey(crypto.S256(), reader)
	if err != nil {
		panic("key generation: ecdsa.GenerateKey failed: " + err.Error())
	}
	key := newKeyFromECDSA(privateKeyECDSA)
	if !strings.HasPrefix(key.Address.Hex(), "0x00") {
		return NewKeyForDirectICAP(rand)
	}
	return key
}

func newKey(rand io.Reader) (*Key, error) {
	privateKeyECDSA, err := ecdsa.GenerateKey(crypto.S256(), rand)
	if err != nil {
		return nil, err
	}
	return newKeyFromECDSA(privateKeyECDSA), nil
}

func storeNewKey(ks keyStore, rand io.Reader, auth string) (*Key, accounts.Account, error) {
	key, err := newKey(rand)
	if err != nil {
		return nil, accounts.Account{}, err
	}
	a := accounts.Account{Address: key.Address, URL: accounts.URL{Scheme: KeyStoreScheme, Path: ks.JoinPath(keyFileName(key.Address))}}
	if err := ks.StoreKey(a.URL.Path, key, auth); err != nil {
		zeroKey(key.PrivateKey)
		return nil, a, err
	}
	return key, a, err
}

func writeKeyFile(file string, content []byte) error {
	// Create the keystore directory with appropriate permissions
	// in case it is not present yet.
	const dirPerm = 0700
	if err := os.MkdirAll(filepath.Dir(file), dirPerm); err != nil {
		return err
	}
	// Atomic write: create a temporary hidden file first
	// then move it into place. TempFile assigns mode 0600.
	f, err := ioutil.TempFile(filepath.Dir(file), "."+filepath.Base(file)+".tmp")
	if err != nil {
		return err
	}
	if _, err := f.Write(content); err != nil {
		f.Close()
		os.Remove(f.Name())
		return err
	}
	f.Close()
	return os.Rename(f.Name(), file)
}

// keyFileName implements the naming convention for keyfiles:
// UTC--<created_at UTC ISO8601>-<address hex>
func keyFileName(keyAddr common.Address) string {
	ts := time.Now().UTC()
	return fmt.Sprintf("UTC--%s--%s", toISO8601(ts), hex.EncodeToString(keyAddr[:]))
}

func toISO8601(t time.Time) string {
	var tz string
	name, offset := t.Zone()
	if name == "UTC" {
		tz = "Z"
	} else {
		tz = fmt.Sprintf("%03d00", offset/3600)
	}
	return fmt.Sprintf("%04d-%02d-%02dT%02d-%02d-%02d.%09d%s", t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), tz)
}

// GeneratePKPairFromABddress represents the keystore to retrieve public key-pair from given Address
func GeneratePKPairFromABaddress(w []byte) (*ecdsa.PublicKey, *ecdsa.PublicKey, error) {
	if len(w) != common.ABaddressLength {
		return nil, nil, ErrABaddressInvalid
	}

	tmp := make([]byte, 33)
	copy(tmp[:], w[:33])
	curve := btcec.S256()
	PK1, err := btcec.ParsePubKey(tmp, curve)
	if err != nil {
		return nil, nil, err
	}

	copy(tmp[:], w[33:])
	PK2, err := btcec.ParsePubKey(tmp, curve)
	if err != nil {
		return nil, nil, err
	}

	PK11 := (*ecdsa.PublicKey)(PK1)
	PK22 := (*ecdsa.PublicKey)(PK2)
	return PK11, PK22, nil
}

func ABaddrFromUncompressedRawBytes(raw []byte) (*common.ABaddress, error) {
	if len(raw) != 32*2*2 {
		return nil, errors.New("invalid uncompressed wan address len")
	}
	pub := make([]byte, 65)
	pub[0] = 0x004
	copy(pub[1:], raw[:64])
	A := crypto.ToECDSAPub(pub)
	copy(pub[1:], raw[64:])
	B := crypto.ToECDSAPub(pub)
	return GenerateABaddressFromPK(A, B), nil
}

func GenerateABaddressFromPK(A *ecdsa.PublicKey, B *ecdsa.PublicKey) *common.ABaddress {
	var tmp common.ABaddress
	copy(tmp[:33], ECDSAPKCompression(A))
	copy(tmp[33:], ECDSAPKCompression(B))
	return &tmp
}

// storeNewABKey save AB account keystore file
func storeNewABKey(ks keyStore, abBaseAddr common.ABaddress, AprivKey *ecdsa.PrivateKey, auth string) (*Key, accounts.Account, error) {

	key, err := newABKey(abBaseAddr, AprivKey)
	if err != nil {
		return nil, accounts.Account{}, err
	}

	a := accounts.Account{Address: key.Address, URL: accounts.URL{Scheme: KeyStoreScheme, Path: ks.JoinPath(keyFileName(key.Address))}}

	if err := ks.StoreKey(a.URL.Path, key, auth); err != nil {
		zeroKey(key.PrivateKey)
		return nil, a, err
	}
	return key, a, err
}

func ABkeyFileName(keyAddr common.ABaddress) string {
	ts := time.Now().UTC()
	return fmt.Sprintf("UTC--%s--%s", toISO8601(ts), hex.EncodeToString(keyAddr[:]))
}

// newABKey generate ABaccount Key
func newABKey(abBaseAddr common.ABaddress, AprivKey *ecdsa.PrivateKey) (*Key, error) {
	A, B, err := GeneratePKPairFromABaddress(abBaseAddr[:])
	if err != nil {
		return nil, err
	}

	PKPairStr := hexutil.PKPair2HexSlice(A, B)
	SKOTA, s, err := crypto.GenerateABKey(PKPairStr[0], PKPairStr[1], PKPairStr[2], PKPairStr[3], AprivKey)
	if err != nil {
		return nil, err
	}

	otaStr := strings.Replace(strings.Join(SKOTA, ""), "0x", "", -1)

	raw, err := hexutil.Decode("0x" + otaStr)
	if err != nil {
		return nil, err
	}

	abRawADDR, err := ABaddrFromUncompressedRawBytes(raw)
	if err != nil || abRawADDR == nil {
		return nil, err
	}

	// transform AB account key result to string
	pk, err := ComputeABKeys(SKOTA[0], SKOTA[1], PKPairStr[2], PKPairStr[3], AprivKey, s)
	if err != nil {
		return nil, err
	}
	if len(pk) != 4 || len(pk[0]) == 0 || len(pk[1]) == 0 || len(pk[2]) == 0 {
		return nil, err
	}
	otaPriv := pk[2]

	privateKeyECDSA, err := crypto.HexToECDSA(otaPriv[2:])
	if err != nil {
		return nil, err
	}

	var addr common.Address
	pubkey := crypto.FromECDSAPub(&privateKeyECDSA.PublicKey)

	//caculate the address for replaced pub
	copy(addr[:], crypto.Keccak256(pubkey[1:])[12:])
	return newABKeyFromECDSA(privateKeyECDSA, s, addr), nil
}

// ComputeABKeys genetate public key and private key of AB account
func ComputeABKeys(AX, AY, BX, BY string, PrivateKey *ecdsa.PrivateKey, s *ecdsa.PrivateKey) ([]string, error) {
	pub1, priv1, priv2, err := crypto.GenerteABPrivateKey(PrivateKey, s, AX, AY, BX, BY)
	pub1X := hexutil.Encode(common.LeftPadBytes(pub1.X.Bytes(), 32))
	pub1Y := hexutil.Encode(common.LeftPadBytes(pub1.Y.Bytes(), 32))
	priv1D := hexutil.Encode(common.LeftPadBytes(priv1.D.Bytes(), 32))
	priv2D := hexutil.Encode(common.LeftPadBytes(priv2.D.Bytes(), 32))
	return []string{pub1X, pub1Y, priv1D, priv2D}, err
}

// newABKeyFromECDSA assign private key and address to Key
func newABKeyFromECDSA(sk1 *ecdsa.PrivateKey, sk2 *ecdsa.PrivateKey, addr common.Address) *Key {
	id := uuid.NewRandom()
	key := &Key{
		Id:          id,
		Address:     addr,
		PrivateKey:  sk1,
		PrivateKey2: sk2,
	}
	updateABaddress(key)
	return key
}

func updateABaddress(k *Key) {
	k.ABaddress = *GenerateABaddressFromPK(&k.PrivateKey.PublicKey, &k.PrivateKey2.PublicKey)
	log.Info("newABaccount infomation", "ABaddress", hexutil.Encode(k.ABaddress[:]))
}
