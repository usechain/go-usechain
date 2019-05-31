package hdwallet

import (
	"crypto/ecdsa"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"sync"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcutil/hdkeychain"
	"github.com/tyler-smith/go-bip39"
	usechain "github.com/usechain/go-usechain"
	"github.com/usechain/go-usechain/accounts"
	"github.com/usechain/go-usechain/common"
	"github.com/usechain/go-usechain/common/hexutil"
	"github.com/usechain/go-usechain/core/types"
	"github.com/usechain/go-usechain/crypto"
)

type HDWallet struct {
	mnemonic  string
	masterKey *hdkeychain.ExtendedKey
	seed      []byte
	url       accounts.URL
	paths     map[common.Address]accounts.DerivationPath
	accounts  []accounts.Account
	stateLock sync.RWMutex
}

func newHDWallet(seed []byte) (*HDWallet, error) {
	masterKey, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		return nil, err
	}

	return &HDWallet{
		masterKey: masterKey,
		seed:      seed,
		accounts:  []accounts.Account{},
		paths:     map[common.Address]accounts.DerivationPath{},
	}, nil
}

func NewFromMnemonic(mnemonic string) (*HDWallet, error) {
	if mnemonic == "" {
		return nil, errors.New("mnemonic is required")
	}

	if !bip39.IsMnemonicValid(mnemonic) {
		return nil, errors.New("mnemonic is invalid")
	}

	seed, err := NewSeedFromMnemonic(mnemonic)
	if err != nil {
		return nil, err
	}

	hdwallet, err := newHDWallet(seed)
	if err != nil {
		return nil, err
	}
	hdwallet.mnemonic = mnemonic

	return hdwallet, nil
}

// NewFromSeed returns a new wallet from a BIP-39 seed.
func NewFromSeed(seed []byte) (*HDWallet, error) {
	if len(seed) == 0 {
		return nil, errors.New("seed is required")
	}

	return newHDWallet(seed)
}

func (w *HDWallet) URL() accounts.URL {
	return w.url
}

func (w *HDWallet) Status() (string, error) {
	return "ok", nil
}

// Open implements accounts.Wallet, however this does nothing since this
// is not a hardware device.
func (w *HDWallet) Open(passphrase string) error {
	return nil
}

// Close implements accounts.Wallet, however this does nothing since this
// is not a hardware device.
func (w *HDWallet) Close() error {
	return nil
}

// Accounts implements accounts.Wallet, returning the list of accounts pinned to
// the wallet. If self-derivation was enabled, the account list is
// periodically expanded based on current chain state.
func (w *HDWallet) Accounts() []accounts.Account {
	// Attempt self-derivation if it's running
	// Return whatever account list we ended up with
	w.stateLock.RLock()
	defer w.stateLock.RUnlock()

	cpy := make([]accounts.Account, len(w.accounts))
	copy(cpy, w.accounts)
	return cpy
}

// Contains implements accounts.Wallet, returning whether a particular account is
// or is not pinned into this wallet instance.
func (w *HDWallet) Contains(account accounts.Account) bool {
	w.stateLock.RLock()
	defer w.stateLock.RUnlock()

	_, exists := w.paths[account.Address]
	return exists
}

// Unpin unpins account from list of pinned accounts.
func (w *HDWallet) Unpin(account accounts.Account) error {
	w.stateLock.RLock()
	defer w.stateLock.RUnlock()

	for i, acct := range w.accounts {
		if acct.Address.String() == account.Address.String() {
			w.accounts = removeAtIndex(w.accounts, i)
			delete(w.paths, account.Address)
			return nil
		}
	}

	return errors.New("account not found")
}

// Derive implements accounts.Wallet, deriving a new account at the specific
// derivation path. If pin is set to true, the account will be added to the list
// of tracked accounts.
func (w *HDWallet) DeriveChild(path accounts.DerivationPath, pin bool) (accounts.Account, error) {
	// Try to derive the actual account and update its URL if successful
	// w.stateLock.RLock() // Avoid device disappearing during derivation

	address, err := w.deriveChildAddress(path)

	// w.stateLock.RUnlock()

	// If an error occurred or no pinning was requested, return
	if err != nil {
		return accounts.Account{}, err
	}

	account := accounts.Account{
		Address: address,
		URL: accounts.URL{
			Scheme: "",
			Path:   path.String(),
		},
	}

	if !pin {
		return account, nil
	}

	// Pinning needs to modify the state
	w.stateLock.Lock()
	defer w.stateLock.Unlock()

	if _, ok := w.paths[address]; !ok {
		w.accounts = append(w.accounts, account)
		w.paths[address] = path
	}

	return account, nil
}

// Derive implements accounts.Wallet, deriving a new account at the specific
// derivation path. If pin is set to true, the account will be added to the list
// of tracked accounts.
func (w *HDWallet) Derive(path accounts.DerivationPath, pin bool) (accounts.Account, error) {
	// Try to derive the actual account and update its URL if successful
	w.stateLock.RLock() // Avoid device disappearing during derivation

	address, err := w.deriveAddress(path)

	w.stateLock.RUnlock()

	// If an error occurred or no pinning was requested, return
	if err != nil {
		return accounts.Account{}, err
	}

	account := accounts.Account{
		Address: address,
		URL: accounts.URL{
			Scheme: "",
			Path:   path.String(),
		},
	}

	if !pin {
		return account, nil
	}

	// Pinning needs to modify the state
	w.stateLock.Lock()
	defer w.stateLock.Unlock()

	if _, ok := w.paths[address]; !ok {
		w.accounts = append(w.accounts, account)
		w.paths[address] = path
	}

	return account, nil
}

// SelfDerive implements accounts.Wallet, trying to discover accounts that the
// user used previously (based on the chain state), but ones that he/she did not
// explicitly pin to the wallet manually. To avoid chain head monitoring, self
// derivation only runs during account listing (and even then throttled).
func (w *HDWallet) SelfDerive(base accounts.DerivationPath, chain usechain.ChainStateReader) {
	// TODO: self derivation
}

// SignHash implements accounts.Wallet, which allows signing arbitrary data.
func (w *HDWallet) SignHash(account accounts.Account, hash []byte) ([]byte, error) {
	// Make sure the requested account is contained within
	path, ok := w.paths[account.Address]
	if !ok {
		return nil, accounts.ErrUnknownAccount
	}

	privateKey, err := w.derivePrivateKey(path)
	if err != nil {
		return nil, err
	}

	return crypto.Sign(hash, privateKey)
}

// SignTx implements accounts.Wallet, which allows the account to sign an Ethereum transaction.
func (w *HDWallet) SignTx(account accounts.Account, tx *types.Transaction, chainID *big.Int) (*types.Transaction, error) {
	w.stateLock.RLock() // Comms have own mutex, this is for the state fields
	defer w.stateLock.RUnlock()

	// Make sure the requested account is contained within
	path, ok := w.paths[account.Address]
	if !ok {
		return nil, accounts.ErrUnknownAccount
	}

	privateKey, err := w.derivePrivateKey(path)
	if err != nil {
		return nil, err
	}

	// Sign the transaction and verify the sender to avoid hardware fault surprises
	signedTx, err := types.SignTx(tx, types.HomesteadSigner{}, privateKey)
	if err != nil {
		return nil, err
	}

	msg, err := signedTx.AsMessage(types.HomesteadSigner{})
	if err != nil {
		return nil, err
	}

	sender := msg.From()
	if sender != account.Address {
		return nil, fmt.Errorf("signer mismatch: expected %s, got %s", account.Address.Hex(), sender.Hex())
	}

	return signedTx, nil
}

// SignHashWithPassphrase implements accounts.Wallet, attempting
// to sign the given hash with the given account using the
// passphrase as extra authentication.
func (w *HDWallet) SignHashWithPassphrase(account accounts.Account, passphrase string, hash []byte) ([]byte, error) {
	return w.SignHash(account, hash)
}

// SignTxWithPassphrase implements accounts.Wallet, attempting to sign the given
// transaction with the given account using passphrase as extra authentication.
func (w *HDWallet) SignTxWithPassphrase(account accounts.Account, passphrase string, tx *types.Transaction, chainID *big.Int) (*types.Transaction, error) {
	return w.SignTx(account, tx, chainID)
}

// PrivateKey returns the ECDSA private key of the account.
func (w *HDWallet) PrivateKey(account accounts.Account) (*ecdsa.PrivateKey, error) {
	path, err := accounts.ParseDerivationPath(account.URL.Path)
	if err != nil {
		return nil, err
	}

	return w.derivePrivateKey(path)
}

// PrivateKeyBytes returns the ECDSA private key in bytes format of the account.
func (w *HDWallet) PrivateKeyBytes(account accounts.Account) ([]byte, error) {
	privateKey, err := w.PrivateKey(account)
	if err != nil {
		return nil, err
	}

	return crypto.FromECDSA(privateKey), nil
}

// PrivateKeyHex return the ECDSA private key in hex string format of the account.
func (w *HDWallet) PrivateKeyHex(account accounts.Account) (string, error) {
	privateKeyBytes, err := w.PrivateKeyBytes(account)
	if err != nil {
		return "", err
	}

	return hexutil.Encode(privateKeyBytes)[2:], nil
}

// PublicKey returns the ECDSA public key of the account.
func (w *HDWallet) PublicKey(account accounts.Account) (*ecdsa.PublicKey, error) {
	path, err := accounts.ParseDerivationPath(account.URL.Path)
	if err != nil {
		return nil, err
	}

	return w.derivePublicKey(path)
}

// PublicKeyBytes returns the ECDSA public key in bytes format of the account.
func (w *HDWallet) PublicKeyBytes(account accounts.Account) ([]byte, error) {
	publicKey, err := w.PublicKey(account)
	if err != nil {
		return nil, err
	}

	return crypto.FromECDSAPub(publicKey), nil
}

// PublicKeyHex return the ECDSA public key in hex string format of the account.
func (w *HDWallet) PublicKeyHex(account accounts.Account) (string, error) {
	publicKeyBytes, err := w.PublicKeyBytes(account)
	if err != nil {
		return "", err
	}

	return hexutil.Encode(publicKeyBytes)[4:], nil
}

// Address returns the address of the account.
func (w *HDWallet) Address(account accounts.Account) (common.Address, error) {
	publicKey, err := w.PublicKey(account)
	if err != nil {
		return common.Address{}, err
	}

	return crypto.PubkeyToAddress(*publicKey), nil
}

// AddressBytes returns the address in bytes format of the account.
func (w *HDWallet) AddressBytes(account accounts.Account) ([]byte, error) {
	address, err := w.Address(account)
	if err != nil {
		return nil, err
	}
	return address.Bytes(), nil
}

// AddressHex returns the address in hex string format of the account.
func (w *HDWallet) AddressHex(account accounts.Account) (string, error) {
	address, err := w.Address(account)
	if err != nil {
		return "", err
	}
	return address.Hex(), nil
}

// Path return the derivation path of the account.
func (w *HDWallet) Path(account accounts.Account) (string, error) {
	return account.URL.Path, nil
}

// MustParseDerivationPath parses the derivation path in string format into
// []uint32 but will panic if it can't parse it.
func MustParseDerivationPath(path string) accounts.DerivationPath {
	parsed, err := accounts.ParseDerivationPath(path)
	if err != nil {
		panic(err)
	}

	return parsed
}

// NewMnemonic returns a randomly generated BIP-39 mnemonic using 128-256 bits of entropy.
func NewMnemonic(bits int) (string, error) {
	entropy, err := bip39.NewEntropy(bits)
	if err != nil {
		return "", err
	}
	return bip39.NewMnemonic(entropy)
}

// NewSeed returns a randomly generated BIP-39 seed.
func NewSeed() ([]byte, error) {
	b := make([]byte, 64)
	_, err := rand.Read(b)
	return b, err
}

// NewSeedFromMnemonic returns a BIP-39 seed based on a BIP-39 mnemonic.
func NewSeedFromMnemonic(mnemonic string) ([]byte, error) {
	if mnemonic == "" {
		return nil, errors.New("mnemonic is required")
	}

	return bip39.NewSeedWithErrorChecking(mnemonic, "")
}

// DeriveAddress derives the account address of the derivation path.
func (w *HDWallet) deriveChildAddress(path accounts.DerivationPath) (common.Address, error) {
	publicKeyECDSA, err := w.deriveChildPublicKey(path)
	if err != nil {
		return common.Address{}, err
	}

	address := crypto.PubkeyToAddress(*publicKeyECDSA)
	return address, nil
}

// DeriveAddress derives the account address of the derivation path.
func (w *HDWallet) deriveAddress(path accounts.DerivationPath) (common.Address, error) {
	publicKeyECDSA, err := w.derivePublicKey(path)
	if err != nil {
		return common.Address{}, err
	}

	address := crypto.PubkeyToAddress(*publicKeyECDSA)
	return address, nil
}

// DerivePrivateKey derives the private key of the derivation path.
func (w *HDWallet) derivePrivateKey(path accounts.DerivationPath) (*ecdsa.PrivateKey, error) {
	var err error
	key := w.masterKey
	for _, n := range path {
		key, err = key.Child(n)
		if err != nil {
			return nil, err
		}
	}

	privateKey, err := key.ECPrivKey()
	privateKeyECDSA := privateKey.ToECDSA()
	if err != nil {
		return nil, err
	}

	return privateKeyECDSA, nil
}

// DerivePublicKey derives the public key of the derivation path.
func (w *HDWallet) derivePublicKey(path accounts.DerivationPath) (*ecdsa.PublicKey, error) {
	privateKeyECDSA, err := w.derivePrivateKey(path)
	if err != nil {
		return nil, err
	}

	publicKey := privateKeyECDSA.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("failed to get public key")
	}

	return publicKeyECDSA, nil
}

func (w *HDWallet) deriveChildPublicKey(path accounts.DerivationPath) (*ecdsa.PublicKey, error) {
	var err error
	// turn private extend key into public extend key
	key, _ := w.masterKey.Neuter()
	for _, n := range path {
		key, err = key.Child(n)
		if err != nil {
			return nil, err
		}
	}
	publicKey, err := key.ECPubKey()
	if err != nil {
		return nil, err
	}
	publicKeyECDSA := publicKey.ToECDSA()
	return publicKeyECDSA, nil
}

// removeAtIndex removes an account at index.
func removeAtIndex(accts []accounts.Account, index int) []accounts.Account {
	return append(accts[:index], accts[index+1:]...)
}

func (w *HDWallet) GetMnemonic() string {
	return w.mnemonic
}
