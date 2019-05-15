// Copyright 2014 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package common

import (
	"math/big"
	"github.com/usechain/go-usechain/common/hexutil"
)

// Common big integers && chain setting often used
var (
	Big1   = big.NewInt(1)
	Big2   = big.NewInt(2)
	Big3   = big.NewInt(3)
	Big0   = big.NewInt(0)
	Big32  = big.NewInt(32)
	Big256 = big.NewInt(256)
	Big257 = big.NewInt(257)

	BlockSlot               = big.NewInt(25)
	VoteSlot                = big.NewInt(10)
	VoteSlotForGenesis      = int64(1000)
	PenaltyBlockTime        = int64(20)
	MisconductLimitsLevel1  = int64(15)
	MisconductLimitsLevel2  = int64(30)
	MisconductLimitsLevel3  = int64(45)
	MaxCommitteemanCount    = 5
	BlockInterval           = 5
	VoteInterval            = uint64(300)
	GenesisMinerQrSignature = hexutil.MustDecode("0xf0a1b27e725547bcac710bac16e6fa2e78354669aa8b4fa77b1b35fe36b78f70158125bec14a9cef5fee276cb9e739a27a8e08c544b8d625b07fe17ce19ebed3009ce48800a25f57fd492e9374cb78a4ef2b91921ed3df829fcee4220de99e2b54")
)