package model

// PubDataVO 共享链数据
type PubDataVO struct {
	RandomKeyX string `json:"RandomKeyX"`
	RandomKeyY string `json:"RandomKeyY"`
	CipherX    string `json:"CipherX"`
	CipherY    string `json:"CipherY"`
	Sender     string `json:"Sender"`
	ShareTime  string `json:ShareTime`
	Version    string `json:Version`
}
