package ca

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/bitly/go-simplejson"
	"github.com/usechain/go-usechain/core/types"
	"github.com/usechain/go-usechain/log"
	"github.com/usechain/go-usechain/node"
)

//CARegResp indicates the response content when applying for a CA certificate.
type CARegResp struct {
	Limit  int
	Offset int
	Order  string
	Status int
	msg    string
	Data   caRegRespData
}
type caRegRespData struct {
	IDKey string
}

// fatalf formats a message to standard error and exits the program.
// The message is also printed to standard output if standard error
// is redirected to a different file.
func fatalf(format string, args ...interface{}) {
	w := io.MultiWriter(os.Stdout, os.Stderr)
	if runtime.GOOS == "windows" {
		// The SameFile check below doesn't work on Windows.
		// stdout is unlikely to get redirected though, so just print there.
		w = os.Stdout
	} else {
		outf, _ := os.Stdout.Stat()
		errf, _ := os.Stderr.Stat()
		if outf != nil && errf != nil && os.SameFile(outf, errf) {
			w = os.Stderr
		}
	}
	fmt.Fprintf(w, "Fatal: "+format+"\n", args...)
	os.Exit(1)
}

//CAVerify user register
func CAVerify(id string, photos []string, caUrl string) (string, error) {
	IDKey, err := UserAuthOperation(id, photos, caUrl)
	if err != nil {
		return "", err
	}
	return IDKey, nil
}

//UserAuthOperation use userID and photo to register ca cert.
func UserAuthOperation(infofile string, photo []string, caUrl string) (string, error) {

	info := string(GetUserData(infofile))
	IDKey, err := postVerifactionData(info, photo, caUrl)
	if err != nil {
		log.Error("Failed to upload user info :", "err", err)
		return "", err
	}
	return IDKey, nil
}
func postVerifactionData(info string, filename []string, caUrl string) (string, error) {
	//Create form
	buf := new(bytes.Buffer)
	writer := multipart.NewWriter(buf)

	//read file and write data to form
	count := 1
	for _, v := range filename {
		formFile, err := writer.CreateFormFile(fmt.Sprintf("uploadfile%d", count), v)
		count++
		if err != nil {
			log.Error("Create form file failed,", "err", err)
			return "", err
		}
		log.Info("v:", v)
		if v == "" {
			log.Error("photo path can not be empty")
			return "", errors.New("photo path can not be empty")
		}
		// read only
		srcFile, err := os.OpenFile(v, os.O_RDONLY, 0)
		if err != nil {
			log.Error("Open source file failed:", "err", err)
			return "", err
		}
		_, err = io.Copy(formFile, srcFile)
		srcFile.Close()
	}

	//add user data field
	idField, err := writer.CreateFormField("data")
	r := strings.NewReader(info) //only id and name for now
	_, err = io.Copy(idField, r)

	//add CSR field
	idHex, fpr, err := geneKeyFromInfo(info)
	if err != nil {
		return "", err
	}
	CSR := geneCSR(idHex, fpr)
	CSRField, err := writer.CreateFormField("csr")
	r = strings.NewReader(CSR)
	_, err = io.Copy(CSRField, r)

	writer.Close()
	contentType := writer.FormDataContentType()
	resp, err := http.Post(caUrl, contentType, buf)
	if err != nil {
		log.Error("Post failed,", "err", err)
		return "", err
	}
	respStr := readerToString(resp.Body)
	fmt.Println(respStr)
	regResp := new(CARegResp)
	err = json.Unmarshal([]byte(respStr), &regResp)
	if err != nil {
		log.Error("unmarshal failed,", "err", err)
		return "", err
	}
	IDKey := regResp.Data.IDKey

	return IDKey, nil
}

// func geneUserData(userID string) string {
// 	values := map[string]string{"userID": userID}
// 	userData, _ := json.Marshal(values)
// 	return string(userData)
// }

// TODO:generate rsa key pair remote
func geneCSR(idHex string, fingerprint string) string {
	keyBytes, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fatalf("Generate RSA key pair error: %v", err)
	}
	publicKey := keyBytes.PublicKey
	separator := string(os.PathSeparator)
	savePEMKey(node.DefaultDataDir()+separator+"userrsa.prv", keyBytes)
	savePublicPEMKey(node.DefaultDataDir()+separator+"userrsa.pub", publicKey)

	subj := pkix.Name{
		CommonName:   idHex,
		SerialNumber: fingerprint,
		// Locality:   []string{idHex},
	}
	rawSubj := subj.ToRDNSequence()
	asn1Subj, _ := asn1.Marshal(rawSubj)
	template := x509.CertificateRequest{
		RawSubject:         asn1Subj,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	csrBytes, _ := x509.CreateCertificateRequest(rand.Reader, &template, keyBytes)
	csrBuf := new(bytes.Buffer)
	pem.Encode(csrBuf, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})

	return csrBuf.String()
}

func geneKeyFromInfo(info string) (string, string, error) {
	if info == "" {
		log.Error("Could not use empty string as ID")
		return "", "", errors.New("Could not use empty string as ID")
	}
	ud := types.JsonToStruct(info)
	return ud.IdHex(), ud.FingerPrint(), nil
}

func savePEMKey(fileName string, key *rsa.PrivateKey) {
	outFile, err := os.Create(fileName)
	checkError(err)
	defer outFile.Close()

	var privateKey = &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}

	err = pem.Encode(outFile, privateKey)
	log.Info("Private key saved at " + fileName)
	checkError(err)
}

func savePublicPEMKey(fileName string, pubkey rsa.PublicKey) {
	asn1Bytes, err := asn1.Marshal(pubkey)
	checkError(err)

	var pemkey = &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: asn1Bytes,
	}

	pemfile, err := os.Create(fileName)
	checkError(err)
	defer pemfile.Close()

	err = pem.Encode(pemfile, pemkey)
	log.Info("Public key saved at " + fileName)
	checkError(err)
}
func readerToString(r io.Reader) string {
	buf := new(bytes.Buffer)
	buf.ReadFrom(r)
	return buf.String()
}
func checkError(err error) {
	if err != nil {
		fatalf("Fatal error ", err.Error())
		// os.Exit(1)
	}
}

// //VerifyQuery after user registered, user can get query info and stores ca file.
// func VerifyQuery(idKey string) error {
// 	err := Query(idKey)
// 	if err != nil {
// 		return err
// 	}
// 	return nil
// }

//Query use idkey as param to query user ca information.
func Query(s string, queryUrl string) error {

	err := queryID(queryUrl, s)
	if err != nil {
		return err
	}
	return nil
}
func queryID(CAserver string, idKey string) error {
	u, _ := url.Parse(CAserver)
	q := u.Query()
	q.Add("idKey", idKey)
	u.RawQuery = q.Encode()
	log.Info("query url for idKey:", "idKey", idKey)
	resp, err := http.Get(u.String())
	if err != nil {
		return err
	}

	CAbuf := new(bytes.Buffer)
	CAbuf.ReadFrom(resp.Body)
	if resp.StatusCode != 200 {
		log.Error(CAbuf.String())
		return fmt.Errorf("Response's statuscode is %d! Please try again later", resp.StatusCode)
	}

	jsondata, _ := simplejson.NewJson(CAbuf.Bytes())
	status, _ := jsondata.Get("status").Int()
	if status != 0 {
		return errors.New("Verification failed, please review your profile and submit later")
	}
	cert, err := jsondata.Get("data").Get("cert").String()
	if err != nil {
		return err
	}

	userCert := node.DefaultDataDir() + string(os.PathSeparator) + "user.crt"
	err = ioutil.WriteFile(userCert, []byte(cert), 0644)
	checkError(err)
	log.Info("CAbuf:", "CAbuf", CAbuf.String())
	log.Info("Verification successful, your CA file stored in " + userCert)

	return nil
}

func GetUserData(filename string) []byte {
	userDataPath := filepath.Join(node.DefaultDataDir(), filename)
	dataBytes, _ := readData(userDataPath)
	return dataBytes
}

// getCert will read user.crt and return certificate string
func GetUserCert(filename string) ([]byte, error) {
	certPath := filepath.Join(node.DefaultDataDir(), filename)
	// parse user certificate
	certBytes, err := readData(certPath)
	return certBytes, err
}

func readData(filename string) ([]byte, error) {
	userData, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Error("Can not read user data", "err", err)
	}
	return userData, err
}
