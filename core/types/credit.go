package types

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
	Cert   string `json:"cert"`
	Alg    string `json:"alg"`
	UseId  string `json:"useid"`
	PubKey string `json:"pubkey"`
	Cdate  string `json:"cdate"`
	Edate  string `json:"edate"`
}

type UserData struct {
	Id        string `json:"id"`
	CertType  string `json:"certtype"`
	Name      string `json:"name"`
	EName     string `json:"ename"`
	Nation    string `json:"nation"`
	Address   string `json:"address"`
	BirthDate string `json:"birthdate"`
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
