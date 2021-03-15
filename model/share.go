package model

import (
	"fmt"
	"math/big"
)

// ShareChannel 共享通道
type ShareChannel struct {
	X  *big.Int // aBX
	Y  *big.Int // aBY
	AX *big.Int // AX
	AY *big.Int // AY
	BX *big.Int // BX
	BY *big.Int // BY
}

// ShareChannelStr 字符串形式
type ShareChannelStr struct {
	XStr  string `json:"XStr"`
	YStr  string `json:"YStr"`
	AXStr string `json:"AXStr"`
	AYStr string `json:"AYStr"`
	BXStr string `json:"BXStr"`
	BYStr string `json:"BYStr"`
}

// ToObj 转换
func (p *ShareChannelStr) ToObj() (*ShareChannel, error) {
	sc := &ShareChannel{}
	sc.AX, _ = new(big.Int).SetString(p.AXStr, 16)
	sc.AY, _ = new(big.Int).SetString(p.AYStr, 16)
	sc.BX, _ = new(big.Int).SetString(p.BXStr, 16)
	sc.BY, _ = new(big.Int).SetString(p.BYStr, 16)
	sc.X, _ = new(big.Int).SetString(p.XStr, 16)
	sc.Y, _ = new(big.Int).SetString(p.YStr, 16)

	return sc, nil
}

// ToStr 转换
func (p *ShareChannel) ToStr() (*ShareChannelStr, error) {
	scStr := &ShareChannelStr{}
	scStr.AXStr = fmt.Sprintf("%x", p.AX)
	scStr.AYStr = fmt.Sprintf("%x", p.AY)
	scStr.BXStr = fmt.Sprintf("%x", p.BX)
	scStr.BYStr = fmt.Sprintf("%x", p.BY)
	scStr.XStr = fmt.Sprintf("%x", p.X)
	scStr.YStr = fmt.Sprintf("%x", p.Y)

	return scStr, nil
}
