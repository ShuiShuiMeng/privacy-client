package model

import "math/big"

// RandomKey 随机密钥
type RandomKey struct {
	D *big.Int
	X *big.Int
	Y *big.Int
}

// RandomKeyStr 随机密钥字符串
type RandomKeyStr struct {
	RXStr string `json:"RXStr"`
	RYStr string `json:"RYStr"`
}
