package types

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
)

// InitArgs represents the args of system contracts initial args
type Init struct {
	Admin          common.Address `json:"admin,omitempty"`
	BtrAddress     common.Address `json:"btrAddress,omitempty"`
	Epoch          *big.Int       `json:"epoch,omitempty"`
	FoundationPool common.Address `json:"foundationPool,omitempty"`
}

type initMarshaling struct {
	Epoch *math.HexOrDecimal256
}
