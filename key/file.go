package key

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"privacy-client/model"
)

// StoreKey 密钥存储到文件
func StoreKey(private *ecdsa.PrivateKey, name, path string) error {
	// 存储私钥文件
	priKeyPath := filepath.Join(path, "key"+name+".pem")
	privateFile, err := os.OpenFile(filepath.Clean(priKeyPath), os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0766)
	if err != nil {
		return err
	}
	// 存储公钥文件
	pubKeyPath := filepath.Join(path, "pub_key"+name+".pem")
	publicFile, err := os.OpenFile(filepath.Clean(pubKeyPath), os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0766)
	if err != nil {
		return err
	}
	// x509编码
	eccPrivateKey, err := x509.MarshalECPrivateKey(private)
	if err != nil {
		return err
	}
	eccPublicKey, err := x509.MarshalPKIXPublicKey(&private.PublicKey)
	if err != nil {
		return err
	}
	// pem编码
	pem.Encode(privateFile, &pem.Block{Type: "ECC PRIVATE KEY", Bytes: eccPrivateKey})
	pem.Encode(publicFile, &pem.Block{Type: "ECC PUBLIC KEY", Bytes: eccPublicKey})
	return nil
}

// LoadPriKey 从文件加载私钥
func LoadPriKey(path string) (*ecdsa.PrivateKey, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	// 读文件
	info, _ := file.Stat()
	buf := make([]byte, info.Size())
	file.Read(buf)
	// pem解码
	block, _ := pem.Decode(buf)
	// x509解码
	privateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return privateKey, nil
}

// LoadPubKey 从文件加载公钥
func LoadPubKey(path string) (*ecdsa.PublicKey, error) {
	// 读取公钥
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	// 读文件
	info, _ := file.Stat()
	buf := make([]byte, info.Size())
	file.Read(buf)
	// pem解密
	block, _ := pem.Decode(buf)
	// x509解密
	publicInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	publicKey := publicInterface.(*ecdsa.PublicKey)
	return publicKey, nil
}

// StoreRandKey 随机密钥保存
func StoreRandKey(rStr, RXStr, RYStr string, user *model.User, path string) error {
	// 随机密钥写入内存,深拷贝
	r, _ := new(big.Int).SetString(rStr, 16)
	RX, _ := new(big.Int).SetString(RXStr, 16)
	RY, _ := new(big.Int).SetString(RYStr, 16)
	user.RandKey = &model.RandomKey{D: r, X: RX, Y: RY}
	// 保存至文件
	file, err := os.Create(filepath.Clean(path))
	if err != nil {
		return err
	}
	defer file.Close()
	writer := bufio.NewWriter(file)

	// 写入r
	writer.WriteString(rStr)
	writer.WriteString("\n")
	// 写入RX
	writer.WriteString(RXStr)
	writer.WriteString("\n")
	// 写入RY
	writer.WriteString(RYStr)
	writer.WriteString("\n")
	writer.Flush()

	return nil
}

// LoadRandKey 加载随机密钥
func LoadRandKey(user *model.User, path string) error {
	file, err := os.Open(filepath.Clean(path))
	if err == nil {
		rd := bufio.NewReader(file)
		// 加载r RX RY
		rStr, _ := rd.ReadString('\n')
		r, _ := new(big.Int).SetString(rStr, 16)
		RXStr, _ := rd.ReadString('\n')
		RX, _ := new(big.Int).SetString(RXStr, 16)
		RYStr, _ := rd.ReadString('\n')
		RY, _ := new(big.Int).SetString(RYStr, 16)
		user.RandKey = &model.RandomKey{D: r, X: RX, Y: RY}
	} else {
		return err
	}
	defer file.Close()

	return nil
}

// StoreShareRecord 存储分享记录
func StoreShareRecord(pubXStr, pubYStr, RXStr, RYStr, rStr string, user *model.User, path string) error {
	return nil
}
