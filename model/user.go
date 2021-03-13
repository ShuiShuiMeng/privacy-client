package model

import (
	"crypto/ecdsa"
)

// User 用户
type User struct {
	Address string
	ShareC  *ShareChannel
	PriKeyA *ecdsa.PrivateKey
	PriKeyB *ecdsa.PrivateKey
	PubKeyA *ecdsa.PublicKey
	PubKeyB *ecdsa.PublicKey
	RandKey *RandomKey
}
