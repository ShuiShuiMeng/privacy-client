package ecc

import (
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"math/big"
	"privacy-client/model"
)

func minus(curve elliptic.Curve, x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int) {
	tmp := big.NewInt(0)
	tmp = tmp.Sub(tmp, y2)
	x, y := curve.Add(x1, y1, x2, tmp)
	return x, y
}

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
	tmpX, tmpY := curve.ScalarMult(user.PubKeyB.X, user.PubKeyB.Y, tmp.Add(r, user.PriKeyA.D).Bytes()) //(r+A)B
	// fmt.Printf("Encrypt:\nX:%x\nY:%x\n", tmpX, tmpY)
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
func Decrypt(user *model.User, CXStr, CYStr, RXStr, RYStr string) (MXStr, MYStr string, err error) {
	curve := elliptic.P256()
	// 转换格式
	CX, _ := new(big.Int).SetString(CXStr, 16)
	CY, _ := new(big.Int).SetString(CYStr, 16)
	RX, _ := new(big.Int).SetString(RXStr, 16)
	RY, _ := new(big.Int).SetString(RYStr, 16)
	// 计算密钥 bR + bA
	bRX, bRY := curve.ScalarMult(RX, RY, user.PriKeyB.D.Bytes())
	bAX, bAY := curve.ScalarMult(user.PubKeyA.X, user.PubKeyA.Y, user.PriKeyB.D.Bytes())
	KX, KY := curve.Add(bRX, bRY, bAX, bAY)

	MX, MY := minus(curve, CX, CY, KX, KY)

	MXStr = fmt.Sprintf("%x", MX)
	MYStr = fmt.Sprintf("%x", MY)

	return MXStr, MYStr, err
}
