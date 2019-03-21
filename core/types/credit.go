package types

import (
	"encoding/json"
	"github.com/usechain/go-usechain/crypto"
)

type Identity struct {
	Data     string `json:"data"`
	Nation   string `json:"nation"`
	Entity   string `json:"entity"`
	Fpr      string `json:"fpr"`
	Alg      string `json:"alg"`
	CertType string `json:"certtype"`
	Ver      string `json:"ver"`
	Cdate    string `json:"cdate"`
}

type Issuer struct {
	Cert   string      `json:"cert"`
	Alg    string      `json:"alg"`
	UseId  string      `json:"useid"`
	PubKey interface{} `json:"pubkey"`
	Cdate  string      `json:"cdate"`
	Edate  string      `json:"edate"`
}

type UserData struct {
	Id       string `json:"id"`
	CertType string `json:"certtype"`
	Sex      string `json:"sex"`
	Name     string `json:"name"`
	EName    string `json:"ename"`
	Nation   string `json:"nation"`
	Addr     string `json:"addr"`
	BirthDay string `json:"birthday"`
}

func (ud *UserData) Marshal() ([]byte, error) {
	bytes, err := json.Marshal(ud)
	return bytes, err
}

func (ud *UserData) IdHex() string {
	id := ud.CertType + "-" + ud.Id
	idHex := crypto.Keccak256Hash([]byte(id)).Hex()
	return idHex
}

func (ud *UserData) IdBytes() []byte {
	id := ud.CertType + "-" + ud.Id
	idbytes := crypto.Keccak256Hash([]byte(id)).Bytes()
	return idbytes
}

func (ud *UserData) FingerPrint() string {
	jsondata, _ := ud.Marshal()
	return crypto.Keccak256Hash(jsondata).Hex()
}

func JsonToStruct(info string) *UserData {
	ud := NewUserData()
	json.Unmarshal([]byte(info), ud)
	return ud
}

func NewUserData() *UserData {
	return &UserData{}
}

func NewIssuer() *Issuer {
	return &Issuer{}
}

func NewIdentity() *Identity {
	return &Identity{}
}
