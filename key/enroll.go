package key

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"privacy-client/model"
)

// Enroll 注册用户
func Enroll(user *model.User, path string) error {
	// 生成 a，A
	curve := elliptic.P256()
	private, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return err
	}
	user.PriKeyA = private
	user.PubKeyA = &private.PublicKey
	// 存储到文件中
	err = StoreKey(private, "A", path)
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
	err = StoreKey(private, "B", path)
	if err != nil {
		return err
	}
	// 生成公钥地址
	user.Address, err = CalcPubAddress(user.PubKeyB.X, user.PubKeyB.Y)
	if err != nil {
		return err
	}
	// 生成共享通道
	user.ShareC, err = CalcChannel(user)
	if err != nil {
		return err
	}

	return nil
}
