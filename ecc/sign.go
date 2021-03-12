package ecc

import (
	"bytes"
	"client/model"
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
)

// Sign 生成签名
func Sign(user *model.User, CX, CY string) (sign string, err error) {
	// 打包数据
	var CBytes bytes.Buffer
	CBytes.Write([]byte(CX))
	CBytes.Write([]byte(CY))
	pt := CBytes.Bytes()
	// 根据明文plaintext和私钥，生成两个big.Ing
	r, s, err := ecdsa.Sign(rand.Reader, user.PriKeyB, pt)
	if err != nil {
		fmt.Println(err)
		return "", err
	}
	// 格式化数据
	rs, err := r.MarshalText()
	if err != nil {
		return "", err
	}
	ss, err := s.MarshalText()
	if err != nil {
		return "", err
	}
	// 将r，s合并（以“+”分割），作为签名返回
	var SBytes bytes.Buffer
	SBytes.Write(rs)
	SBytes.Write([]byte(`+`))
	SBytes.Write(ss)
	return string(SBytes.Bytes()), nil
}
