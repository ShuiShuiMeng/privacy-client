package key

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"privacy-client/model"

	"github.com/itchyny/base58-go"
	"golang.org/x/crypto/ripemd160"
)

func minus(curve elliptic.Curve, x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int) {
	tmp := big.NewInt(0)
	tmp = tmp.Sub(tmp, y2)
	x, y := curve.Add(x1, y1, x2, tmp)
	return x, y
}

// CalcPubAddress 生成公钥地址
func CalcPubAddress(pubX, pubY *big.Int) (string, error) {
	// 转换成16进制字符串
	pubKeyX := fmt.Sprintf("%x", pubX)
	pubKeyY := fmt.Sprintf("%x", pubY)
	// 拼接
	toBeHashed := "04" + pubKeyX + pubKeyY
	// 计算SHA-256哈希值
	hashBytes := sha256.Sum256([]byte(toBeHashed))
	hashStr := hex.EncodeToString(hashBytes[:])
	// 计算RIPEMD-160哈希值
	pubHasher := ripemd160.New()
	pubHasher.Write([]byte(hashStr))
	pubHashBytes := pubHasher.Sum(nil)
	pubHashStr := hex.EncodeToString(pubHashBytes[:])
	// 增加地址版本号
	verHash := "01" + pubHashStr
	// 进行两次哈希
	hashBytes1 := sha256.Sum256([]byte(verHash))
	hashStr1 := hex.EncodeToString(hashBytes1[:])
	hashBytes2 := sha256.Sum256([]byte(hashStr1))
	hashStr2 := hex.EncodeToString(hashBytes2[:])
	// 组合用户地址
	addressHex := verHash + hashStr2[0:8]
	// 转换成10进制数字用于编码
	addressDec, ok := big.NewInt(0).SetString(addressHex, 16)
	if !ok {
		return "", fmt.Errorf("SetString: error")
	}
	// BASE58编码
	encoding := base58.FlickrEncoding
	encoded, err := encoding.Encode([]byte(addressDec.String()))
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}

// CalcK 计算密钥差值
func CalcK(sc *model.ShareChannel, user *model.User) (KX, KY *big.Int, err error) {
	curve := elliptic.P256()
	// 生成新的随机密钥
	r, _ := rand.Int(rand.Reader, curve.Params().N)
	RX, RY := curve.ScalarBaseMult(r.Bytes())

	tmpX, tmpY := curve.ScalarMult(sc.PubX, sc.PubY, r.Bytes()) // r'E
	tmpX, tmpY = curve.Add(tmpX, tmpY, sc.X, sc.Y)              // dE+r'E

	tmpX1, tmpY1 := curve.Add(user.PubKeyA.X, user.PubKeyA.Y, RX, RY)     // A+R1
	tmpX1, tmpY1 = curve.ScalarMult(tmpX1, tmpY1, user.PriKeyB.D.Bytes()) // b(A+R1)
	KX, KY = minus(curve, tmpX, tmpY, tmpX1, tmpY1)                       // K=dE+r2E-b(A+R1)

	return KX, KY, err
}

// CalcChannel 计算共享通道
func CalcChannel(user *model.User) (*model.ShareChannel, error) {
	curve := elliptic.P256()
	shareX, shareY := curve.ScalarMult(user.PubKeyB.X, user.PubKeyB.Y, user.PriKeyA.D.Bytes())
	shareC := &model.ShareChannel{
		X:    shareX,
		Y:    shareY,
		PubX: user.PubKeyB.X,
		PubY: user.PubKeyB.Y,
	}
	return shareC, nil
}
