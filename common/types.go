// Copyright 2015 The go-ethereum Authors
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

package common

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"math/rand"
	"reflect"
	"time"

	"github.com/usechain/go-usechain/common/base58"
	"github.com/usechain/go-usechain/common/hexutil"
	"github.com/usechain/go-usechain/crypto/sha3"
)

const (
	HashLength          = 32
	AddressLength       = 20
	Base58AddressLength = 35
	SubAddressLength    = 66
)

var (
	IDVerified = uint64(math.Pow(2, 0))
)

var (
	hashT    = reflect.TypeOf(Hash{})
	addressT = reflect.TypeOf(Address{})
)

// Hash represents the 32 byte Keccak256 hash of arbitrary data.
type Hash [HashLength]byte

func BytesToHash(b []byte) Hash {
	var h Hash
	h.SetBytes(b)
	return h
}

// IsHexAddress verifies whether a string can represent a valid hex-encoded
// Ethereum address or not.
func IsHexHash(s string) bool {
	if hasHexPrefix(s) {
		s = s[2:]
	}
	return len(s) == 2*HashLength && isHex(s)
}

func StringToHash(s string) Hash { return BytesToHash([]byte(s)) }
func BigToHash(b *big.Int) Hash  { return BytesToHash(b.Bytes()) }
func HexToHash(s string) Hash    { return BytesToHash(FromHex(s)) }

// Get the string representation of the underlying hash
func (h Hash) Str() string   { return string(h[:]) }
func (h Hash) Bytes() []byte { return h[:] }
func (h Hash) Big() *big.Int { return new(big.Int).SetBytes(h[:]) }
func (h Hash) Hex() string   { return hexutil.Encode(h[:]) }

// TerminalString implements log.TerminalStringer, formatting a string for console
// output during logging.
func (h Hash) TerminalString() string {
	return fmt.Sprintf("%x…%x", h[:3], h[29:])
}

// String implements the stringer interface and is used also by the logger when
// doing full logging into a file.
func (h Hash) String() string {
	return h.Hex()
}

// Increase hash number in Hex
func (h Hash) IncreaseHex(n *big.Int) Hash {
	x := h.Big()
	y := n
	x.Add(x, y)
	return BigToHash(x)
}

// Decrease hash number in Hex
func (h Hash) DecreaseHex(n *big.Int) Hash {
	x := h.Big()
	y := n
	x.Sub(x, y)
	return BigToHash(x)
}

// Format implements fmt.Formatter, forcing the byte slice to be formatted as is,
// without going through the stringer interface used for logging.
func (h Hash) Format(s fmt.State, c rune) {
	fmt.Fprintf(s, "%"+string(c), h[:])
}

// UnmarshalText parses a hash in hex syntax.
func (h *Hash) UnmarshalText(input []byte) error {
	return hexutil.UnmarshalFixedText("Hash", input, h[:])
}

// UnmarshalJSON parses a hash in hex syntax.
func (h *Hash) UnmarshalJSON(input []byte) error {
	return hexutil.UnmarshalFixedJSON(hashT, input, h[:])
}

// MarshalText returns the hex representation of h.
func (h Hash) MarshalText() ([]byte, error) {
	return hexutil.Bytes(h[:]).MarshalText()
}

// Sets the hash to the value of b. If b is larger than len(h), 'b' will be cropped (from the left).
func (h *Hash) SetBytes(b []byte) {
	if len(b) > len(h) {
		b = b[len(b)-HashLength:]
	}

	copy(h[HashLength-len(b):], b)
}

// Set string `s` to h. If s is larger than len(h) s will be cropped (from left) to fit.
func (h *Hash) SetString(s string) { h.SetBytes([]byte(s)) }

// Sets h to other
func (h *Hash) Set(other Hash) {
	for i, v := range other {
		h[i] = v
	}
}

// Generate implements testing/quick.Generator.
func (h Hash) Generate(rand *rand.Rand, size int) reflect.Value {
	m := rand.Intn(len(h))
	for i := len(h) - 1; i > m; i-- {
		h[i] = byte(rand.Uint32())
	}
	return reflect.ValueOf(h)
}

func EmptyHash(h Hash) bool {
	return h == Hash{}
}

// UnprefixedHash allows marshaling a Hash without 0x prefix.
type UnprefixedHash Hash

// UnmarshalText decodes the hash from hex. The 0x prefix is optional.
func (h *UnprefixedHash) UnmarshalText(input []byte) error {
	return hexutil.UnmarshalFixedUnprefixedText("UnprefixedHash", input, h[:])
}

// MarshalText encodes the hash as hex.
func (h UnprefixedHash) MarshalText() ([]byte, error) {
	return []byte(hex.EncodeToString(h[:])), nil
}

// return the string data that has been added to the num
func IncreaseHexByNum(indexKeyHash []byte, num int64) string {
	x := new(big.Int).SetBytes(indexKeyHash)
	y := big.NewInt(num)
	x.Add(x, y)
	return hex.EncodeToString(x.Bytes())
}

// Address represents the 20 byte address of an Ethereum account.
type Address [AddressLength]byte

// SubAddress represents the 66 byte address of an Usechain sub account
type SubAddress [SubAddressLength]byte

func BytesToAddress(b []byte) Address {
	var a Address
	a.SetBytes(b)
	return a
}
func StringToAddress(s string) Address { return BytesToAddress([]byte(s)) }
func BigToAddress(b *big.Int) Address  { return BytesToAddress(b.Bytes()) }
func HexToAddress(s string) Address    { return BytesToAddress(FromHex(s)) }

// IsHexAddress verifies whether a string can represent a valid hex-encoded
// Ethereum address or not.
func IsHexAddress(s string) bool {
	if hasHexPrefix(s) {
		s = s[2:]
	}
	return len(s) == 2*AddressLength && isHex(s)
}

// Get the string representation of the underlying address
func (a Address) Str() string   { return AddressToBase58Address(a).String() }
func (a Address) Bytes() []byte { return a[:] }
func (a Address) Big() *big.Int { return new(big.Int).SetBytes(a[:]) }
func (a Address) Hash() Hash    { return BytesToHash(a[:]) }

// Hex returns an EIP55-compliant hex string representation of the address.
func (a Address) Hex() string {
	unchecksummed := hex.EncodeToString(a[:])
	sha := sha3.NewKeccak256()
	sha.Write([]byte(unchecksummed))
	hash := sha.Sum(nil)

	result := []byte(unchecksummed)
	for i := 0; i < len(result); i++ {
		hashByte := hash[i/2]
		if i%2 == 0 {
			hashByte = hashByte >> 4
		} else {
			hashByte &= 0xf
		}
		if result[i] > '9' && hashByte > 7 {
			result[i] -= 32
		}
	}
	return "0x" + string(result)
}

// String implements the stringer interface and is used also by the logger.
func (a Address) String() string {
	return a.Hex()
}

// Format implements fmt.Formatter, forcing the byte slice to be formatted as is,
// without going through the stringer interface used for logging.
func (a Address) Format(s fmt.State, c rune) {
	fmt.Fprintf(s, "%"+string(c), a.Str())
}

// Sets the address to the value of b. If b is larger than len(a) it will panic
func (a *Address) SetBytes(b []byte) {
	if len(b) > len(a) {
		b = b[len(b)-AddressLength:]
	}
	copy(a[AddressLength-len(b):], b)
}

// Set string `s` to a. If s is larger than len(a) it will panic
func (a *Address) SetString(s string) { a.SetBytes([]byte(s)) }

// Sets a to other
func (a *Address) Set(other Address) {
	for i, v := range other {
		a[i] = v
	}
}

// MarshalText returns the hex representation of a.
func (a Address) MarshalText() ([]byte, error) {
	return []byte(AddressToBase58Address(a).String()), nil
}

// UnmarshalText parses a hash in hex syntax.
func (a *Address) UnmarshalText(input []byte) error {
	address := Base58AddressToAddress(BytesToBase58Address(input))
	*a = address
	return nil
}

// UnmarshalJSON parses a hash in hex syntax.
func (a *Address) UnmarshalJSON(input []byte) error {
	address := Base58AddressToAddress(BytesToBase58Address(input[1 : 1+Base58AddressLength]))
	*a = address
	return nil
}

// UnprefixedHash allows marshaling an Address without 0x prefix.
type UnprefixedAddress Address

// UnmarshalText decodes the address from hex. The 0x prefix is optional.
func (a *UnprefixedAddress) UnmarshalText(input []byte) error {
	address := Base58AddressToAddress(BytesToBase58Address(input))
	*a = UnprefixedAddress(address)
	return nil
}

// MarshalText encodes the address as hex.
func (a UnprefixedAddress) MarshalText() ([]byte, error) {
	return []byte(AddressToBase58Address(Address(a)).String()), nil
}

// Base58Address represents the 35 byte address of an Usechain account
type Base58Address [Base58AddressLength]byte

func (a *Base58Address) SetBytes(b []byte) {
	if len(b) > len(a) {
		b = b[len(b)-Base58AddressLength:]
	}
	copy(a[Base58AddressLength-len(b):], b)
}

func BytesToBase58Address(b []byte) Base58Address {
	var a Base58Address
	a.SetBytes(b)
	return a
}

func (a Base58Address) Bytes() []byte              { return a[:] }
func (a Base58Address) String() string             { return string(a[:]) }
func StringToBase58Address(s string) Base58Address { return BytesToBase58Address([]byte(s)) }

func AddressToBase58Address(a Address) Base58Address {
	versionBuf := append(base58.PREFIX_ADDR, a.Bytes()...)

	firstSHA := sha256.Sum256(versionBuf)
	secondSHA := sha256.Sum256(firstSHA[:])
	checksum := secondSHA[:4]

	allBuf := append(versionBuf, checksum...)
	address := base58.Base58Encode(allBuf)
	return BytesToBase58Address(address)
}

func Base58AddressToAddress(a Base58Address) Address {
	buf := base58.Base58Decode(a.Bytes())
	return BytesToAddress(buf[2 : 2+AddressLength])
}

func UmAddressToAddress(strUmAddress string) Address {
	return Base58AddressToAddress(StringToBase58Address(strUmAddress))
}

func UmAddressToHexAddress(strUmAddress string) string {
	return UmAddressToAddress(strUmAddress).Str()
}

func HexAddressToBase58Address(strHexAddress string) Base58Address {
	return AddressToBase58Address(StringToAddress(strHexAddress))
}
func HexAddressToUmAddress(strHexAddress string) string {
	return HexAddressToBase58Address(strHexAddress).String()
}

func AddressToUmAddress(a Address) string {
	return AddressToBase58Address(a).String()
}

type Lock struct {
	Permission    uint16   `json:"permission"`
	TimeLimit     string   `json:"timelimit"`
	LockedBalance *big.Int `json:"lockedbalance"`
}

func (l Lock) Marshal() ([]byte, error) {
	return json.Marshal(l)
}

func (l Lock) String() string {
	b, _ := l.Marshal()
	return string(b[:])
}

func (l Lock) Expired() bool {
	if l.Permission == 0 {
		return true
	}
	if len(l.TimeLimit) == 0 {
		return false
	}
	now := time.Now()
	expire, err := time.Parse(time.RFC3339, l.TimeLimit)
	if err != nil {
		return false // lock forever if time can not parse correctly
	}
	return expire.Before(now)
}
