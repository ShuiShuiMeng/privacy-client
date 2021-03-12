package key

import (
	"client/model"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
)

// Enroll 注册用户
func Enroll(user *model.User) error {
	// 生成 a，A
	curve := elliptic.P256()
	private, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return err
	}
	user.PriKeyA = private
	user.PubKeyA = &private.PublicKey
	// 存储到文件中
	err = StoreKey(private, "A")
	if err != nil {
		return err
	}
	// 生成 b，B
	private, err = ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return err
	}
	user.PriKeyB = private
	user.PubKeyB = &private.PublicKey
	// 存储到文件中
	err = StoreKey(private, "B")
	if err != nil {
		return err
	}
	// 生成公钥地址
	user.Address, err = CalcPubAddress(user.PubKeyB.X, user.PubKeyB.Y)
	if err != nil {
		return err
	}
	return nil
}
