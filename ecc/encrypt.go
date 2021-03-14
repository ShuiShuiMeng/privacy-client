package ecc

import (
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"math/big"
	"privacy-client/model"
)

// Encrypt 加密函数
func Encrypt(user *model.User, MXstr, MYstr string) (CXstr, CYstr, RXstr, RYstr, rstr string, err error) {
	// 生成随机密钥
	curve := elliptic.P256()
	tmp := big.NewInt(0)
	r, err := rand.Int(rand.Reader, curve.Params().N)
	if err != nil {
		return "", "", "", "", "", err
	}
	// 转换明文格式为16进制
	MX, ok := new(big.Int).SetString(MXstr, 16)
	if !ok {
		return "", "", "", "", "", fmt.Errorf("SetString Error: MX")
	}
	MY, ok := new(big.Int).SetString(MYstr, 16)
	if !ok {
		return "", "", "", "", "", fmt.Errorf("SetString Error: MY")
	}
	// 计算密文C
	tmpX, tmpY := curve.ScalarMult(user.PubKeyB.X, user.PubKeyB.Y, tmp.Add(r, user.PriKeyA.D).Bytes())
	CX, CY := curve.Add(MX, MY, tmpX, tmpY)
	CXstr = fmt.Sprintf("%x", CX)
	CYstr = fmt.Sprintf("%x", CY)
	// 计算R
	RX, RY := curve.ScalarBaseMult(r.Bytes())
	RXstr = fmt.Sprintf("%x", RX)
	RYstr = fmt.Sprintf("%x", RY)
	rstr = fmt.Sprintf("%x", r)

	return CXstr, CYstr, RXstr, RYstr, rstr, nil
}

// Decrypt 解密函数
func Decrypt() {

}
