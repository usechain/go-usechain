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

package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/usechain/go-usechain/common"
	"github.com/usechain/go-usechain/log"
	"io/ioutil"
	"math/big"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"time"
)

// GenerateRSAKeypair generate RSA format public key and private key
func GenerateRSAKeypair() error {
	reader := rand.Reader
	bitSize := 2048
	key, err := rsa.GenerateKey(reader, bitSize)
	if err != nil {
		return err
	}

	publicKey := &key.PublicKey
	BaseDir := DefaultDataDir()
	err = savePEMKey(BaseDir+"/userrsa.prv", key)
	if err != nil {
		return err
	}

	err = savePublicPEMKey(BaseDir+"/userrsa.pub", publicKey)
	if err != nil {
		return err
	}

	return nil
}

// savePEMKey save rsa privatekey with pem format
func savePEMKey(fileName string, key *rsa.PrivateKey) error {
	outFile, err := os.Create(fileName)
	if err != nil {
		log.Error("private key err", err)
	}
	defer outFile.Close()

	var privateKey = &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}
	err = pem.Encode(outFile, privateKey)
	return err
}

// savePublicPEMKey save RSA publickkey with pem format
func savePublicPEMKey(fileName string, pubkey *rsa.PublicKey) error {
	asn1Bytes, err := x509.MarshalPKIXPublicKey(pubkey)
	if err != nil {
		log.Error("public err: ", err)
	}
	var pemkey = &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: asn1Bytes,
	}
	pemfile, err := os.Create(fileName)
	defer pemfile.Close()
	err = pem.Encode(pemfile, pemkey)
	return err
}

// loadPrivateKey loads an parses a PEM encoded private key file.
func loadPublicKey(path string) (Unsigner, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parsePublicKey(data)
}

// parsePublicKey parses a PEM encoded private key.
func parsePublicKey(pemBytes []byte) (Unsigner, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("ssh: no key found")
	}
	var rawkey interface{}
	switch block.Type {
	case "PUBLIC KEY":
		rsaa, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			log.Error("ParsePKIXPublicKey error: ", err)
			return nil, err
		}
		rawkey = rsaa
	default:
		return nil, fmt.Errorf("ssh: unsupported key type %q", block.Type)
	}
	return newUnsignerFromKey(rawkey)
}

// loadPrivateKey loads an parses a PEM encoded private key file.
func loadPrivateKey(path string) (Signer, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		log.Error("Read private key file error: ", err)
		return nil, err
	}
	return parsePrivateKey(data)
}

// parsePublicKey parses a PEM encoded private key.
func parsePrivateKey(pemBytes []byte) (Signer, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("ssh: no key found")
	}
	var rawkey interface{}
	switch block.Type {
	case "PRIVATE KEY":
		rsaa, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		rawkey = rsaa
	default:
		return nil, fmt.Errorf("ssh: unsupported key type %q", block.Type)
	}
	return newSignerFromKey(rawkey)
}

// A Signer is can create signatures that verify against a public key.
type Signer interface {
	// Sign returns raw signature for the given data. This method
	// will apply the hash specified for the keytype to the data.
	Sign(data []byte) ([]byte, error)
}

// A Signer is can create signatures that verify against a public key.
type Unsigner interface {
	// Sign returns raw signature for the given data. This method
	// will apply the hash specified for the keytype to the data.
	Unsign(data []byte) ([]byte, error)
	VerifySign(message []byte, sig []byte) error
}

func newSignerFromKey(k interface{}) (Signer, error) {
	var sshKey Signer
	switch t := k.(type) {
	case *rsa.PrivateKey:
		sshKey = &rsaPrivateKey{t}
	default:
		return nil, fmt.Errorf("ssh: unsupported key type %T", k)
	}
	return sshKey, nil
}

func newUnsignerFromKey(k interface{}) (Unsigner, error) {
	var sshKey Unsigner
	switch t := k.(type) {
	case *rsa.PublicKey:
		sshKey = &rsaPublicKey{t}
	default:
		return nil, fmt.Errorf("ssh: unsupported key type %T", k)
	}
	return sshKey, nil
}

type rsaPublicKey struct {
	*rsa.PublicKey
}

type rsaPrivateKey struct {
	*rsa.PrivateKey
}

// Sign signs data with rsa-sha256
func Hash(data []byte) {
	h := sha256.New()
	h.Write(data)
	h.Sum(nil)
	return
}

// Sign signs data with rsa-sha256
func (r *rsaPrivateKey) Sign(data []byte) ([]byte, error) {
	h := sha256.New()
	h.Write(data)
	d := h.Sum(nil)
	return rsa.SignPKCS1v15(rand.Reader, r.PrivateKey, crypto.SHA256, d)
}

// Unsign encrypts data with rsa-sha256
func (r *rsaPublicKey) Unsign(message []byte) ([]byte, error) {
	return rsa.EncryptPKCS1v15(rand.Reader, r.PublicKey, message)
}

// VerifySign verifies the message using a rsa-sha256 signature
func (r *rsaPublicKey) VerifySign(message []byte, sig []byte) error {
	h := sha256.New()
	h.Write(message)
	d := h.Sum(nil)
	return rsa.VerifyPKCS1v15(r.PublicKey, crypto.SHA256, d, sig)
}

func RSA_Sign(message string) (string, error) {
	BaseDir := DefaultDataDir()
	signer, err := loadPrivateKey(BaseDir + "/userrsa.prv")
	if err != nil {
		log.Error("RSA is not found:", "error", err)
		return "", err
	}

	signed, err := signer.Sign([]byte(message))
	if err != nil {
		fmt.Errorf("could not sign request: %v", err)
		return "", err
	}

	sig := hex.EncodeToString(signed)
	return sig, nil
}

// RSA_Verify verify RSA signature
func RSA_Verify(message string, sig string) bool {
	BaseDir := DefaultDataDir()
	parser, err := loadPublicKey(BaseDir + "/userrsa.pub")
	if err != nil {
		log.Error("public could not sign request:", "error", err)
		return false
	}

	signed, err := hex.DecodeString(sig)
	if err != nil {
		fmt.Errorf("could not sign request: %v", err)
		return false
	}

	err = parser.VerifySign([]byte(message), signed)
	return err == nil
}

func RSA_Verify_Pub(message string, sig string, pub *rsa.PublicKey) bool {
	signed, err := hex.DecodeString(sig)
	if err != nil {
		fmt.Errorf("could not sign request: %v", err)
	}

	h := sha256.New()
	h.Write([]byte(message))
	d := h.Sum(nil)

	rsa.VerifyPKCS1v15(pub, crypto.SHA256, d, signed)
	return err == nil
}

func RSA_Verify_Standard(message string, sig string, pubKey interface{}) error {
	parser, err := newUnsignerFromKey(pubKey)
	if err != nil {
		log.Error("public could not sign request:", "error", err)
		return err
	}

	signed, err := hex.DecodeString(sig)
	if err != nil {
		fmt.Errorf("could not sign request: %v", err)
		return err
	}

	err = parser.VerifySign([]byte(message), signed)
	return err
}

// GenRCA generate root certificate
func GenRCA(emailAddress string, isCA bool, caName string, privName string, pubName string) error {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Error("failed to generate serial number", "err", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Country:      []string{"CN"},
			Organization: []string{"UseChain"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(10, 0, 0),

		KeyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	template.DNSNames = append(template.DNSNames, "localhost")
	template.EmailAddresses = append(template.EmailAddresses, emailAddress)

	if isCA {
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign
	}
	pub := publicKey(priv)
	rcaCert, err := x509.CreateCertificate(rand.Reader, &template, &template, pub, priv)
	if err != nil {
		log.Error("Failed to create certificate:", "err", err)
	}

	BaseDir := DefaultDataDir()
	err = SaveCA(BaseDir+"/RSA_RCA.crt", rcaCert)
	if err != nil {
		return err
	}

	err = savePEMKey(BaseDir+"/RSA_RCA_private.pem", priv)
	if err != nil {
		return err
	}
	return nil
}

func publicKey(priv interface{}) interface{} {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	default:
		return nil
	}
}

//SaveCA save certificate with pem format
func SaveCA(caName string, cert []byte) error {
	certOut, err := os.Create(caName)
	if err != nil {
		log.Error("failed to open for writing:", "err", err)
		return err
	}
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: cert})
	certOut.Close()
	return nil
}

// ReadUserCert read userCert from
func ReadUserCert() string {
	BaseDir := DefaultDataDir()
	f, err := ioutil.ReadFile(BaseDir + "/user.crt")
	if err != nil {
		log.Error("ReadFile err:", "err", err)
	}

	userCertString := hex.EncodeToString(f)
	return userCertString
}

///TODO:add error check
func parseRcaRsa() (*x509.Certificate, error) {
	BaseDir := DefaultDataDir()
	rcaFile, err := ioutil.ReadFile(BaseDir + "/rca.crt")
	if err != nil {
		log.Error("ReadFile err:", "err", err)
		return nil, err
	}

	rcaBlock, _ := pem.Decode(rcaFile)
	if rcaBlock == nil {
		return nil, err
	}

	Cert, err := x509.ParseCertificate(rcaBlock.Bytes)
	if err != nil {
		log.Error("ParseCertificate err:", "err", err)
		return nil, err
	}
	return Cert, nil
}

func CheckUserRegisterCert(cert []byte, userId string) error {
	rcaCert, err := parseRcaRsa()
	if err != nil {
		return err
	}
	certBlock, _ := pem.Decode(cert)
	if certBlock == nil {
		return errors.New("User's cert not found!")
	}
	userCert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return err
	}
	err = userCert.CheckSignatureFrom(rcaCert)
	if err != nil {
		return err
	}

	if userCert.Subject.String()[3:] != userId {
		err = errors.New("Not the right cert of this user")
	}

	return err
}

// CheckUserCert verify user certificate
func CheckUserCert(userCert string) bool {
	rcaCert, err := parseRcaRsa()
	if err != nil {
		return false
	}

	//certToByte,err:=hexutil.Decode(userCert)
	certToByte, err := hex.DecodeString(userCert)
	if err != nil {
		log.Error("user's certificate format error")
		return false
	}

	Block, _ := pem.Decode(certToByte)
	if Block == nil {
		log.Error("ecaFile error")
	}

	userCert2, err := x509.ParseCertificate(Block.Bytes)
	if err != nil {
		log.Error("ParseCertificate err:", "err", err)
		return false
	}

	err = userCert2.CheckSignatureFrom(rcaCert)
	//log.Info("check eCert signature: ", "err", err == nil)
	return err == nil
}

// CheckUserCertStandard verify user certificate
func CheckUserCertStandard(userCert string, addr common.Address, signature []byte) error {
	rcaCert, err := parseRcaRsa()
	if err != nil {
		return err
	}

	//certToByte,err:=hexutil.Decode(userCert)
	certToByte, err := hex.DecodeString(userCert)
	if err != nil {
		log.Error("user's certificate format error")
		return err
	}

	Block, _ := pem.Decode(certToByte)
	if Block == nil {
		log.Error("ecaFile error")
	}

	userCert2, err := x509.ParseCertificate(Block.Bytes)
	if err != nil {
		log.Error("ParseCertificate err:", "err", err)
		return err
	}

	err = userCert2.CheckSignatureFrom(rcaCert)
	//log.Info("check eCert signature: ", "err", err)
	if err != nil {
		return err
	}

	///TODO:change the RSA_Verify_Pub to CheckSignature, to support more signatureAlgorithm
	k := rcaCert.PublicKey
	switch t := k.(type) {
	case *rsa.PublicKey:
		sshKey := &rsaPublicKey{t}
		err := RSA_Verify_Pub(addr.String(), hex.EncodeToString(signature), sshKey.PublicKey)
		if err == false {
			return errors.New("address signature verify failed")
		}

	default:
		log.Info("address signature verify passed")
	}

	//log.Info("check address signature: ", "err", err)
	return nil
}

// DefaultDataDir is the default data directory to use for the databases and other
// persistence requirements.
func DefaultDataDir() string {
	// Try to place the data folder in the user's home dir
	home := homeDir()
	if home != "" {
		if runtime.GOOS == "darwin" {
			return filepath.Join(home, "Library", "usechain")
		} else if runtime.GOOS == "windows" {
			return filepath.Join(home, "AppData", "Roaming", "usechain")
		} else {
			return filepath.Join(home, ".usechain")
		}
	}
	// As we cannot guess a stable location, return empty and handle later
	return ""
}

func homeDir() string {
	if home := os.Getenv("HOME"); home != "" {
		return home
	}
	if usr, err := user.Current(); err == nil {
		return usr.HomeDir
	}
	return ""
}
