package model

import (
	"crypto/ecdsa"
)

type User struct {
	Address string
	PriKeyA *ecdsa.PrivateKey
	PriKeyB *ecdsa.PrivateKey
	PubKeyA *ecdsa.PublicKey
	PubKeyB *ecdsa.PublicKey
	RandKey *RandomKey
}
