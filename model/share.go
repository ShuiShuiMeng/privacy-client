package model

import "math/big"

// ShareChannel 共享通道
type ShareChannel struct {
	X    *big.Int // aBX
	Y    *big.Int // aBY
	PubX *big.Int // BX
	PubY *big.Int // BY
}
