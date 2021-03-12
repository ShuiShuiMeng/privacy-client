package key

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/itchyny/base58-go"
	"golang.org/x/crypto/ripemd160"
)

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
