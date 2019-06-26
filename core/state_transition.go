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

package core

import (
	"encoding/json"
	"errors"
	"math"
	"math/big"

	"github.com/usechain/go-usechain/common"
	"github.com/usechain/go-usechain/common/hexutil"
	"github.com/usechain/go-usechain/core/types"
	"github.com/usechain/go-usechain/core/vm"
	"github.com/usechain/go-usechain/log"
	"github.com/usechain/go-usechain/params"
)

var (
	errInsufficientBalanceForGas = errors.New("insufficient balance to pay for gas")
)

/*
The State Transitioning Model

A state transition is a change made when a transaction is applied to the current world state
The state transitioning model does all all the necessary work to work out a valid new state root.

1) Nonce handling
2) Pre pay gas
3) Create a new state object if the recipient is \0*32
4) Value transfer
== If contract creation ==
  4a) Attempt to run transaction data
  4b) If valid, use result as code for the new state object
== end ==
5) Run Script section
6) Derive new state root
*/
type StateTransition struct {
	gp         *GasPool
	msg        Message
	gas        uint64
	gasPrice   *big.Int
	initialGas uint64
	value      *big.Int
	data       []byte
	state      vm.StateDB
	evm        *vm.EVM
}

// Message represents a message sent to a contract.
type Message interface {
	Flag() uint8

	From() common.Address
	//FromFrontier() (common.Address, error)
	To() *common.Address

	GasPrice() *big.Int
	Gas() uint64
	Value() *big.Int

	Nonce() uint64
	CheckNonce() bool
	Data() []byte
}

// IntrinsicGas computes the 'intrinsic gas' for a message with the given data.
func IntrinsicGas(data []byte, contractCreation, homestead bool) (uint64, error) {
	// Set the starting gas for the raw transaction
	var gas uint64
	if contractCreation && homestead {
		gas = params.TxGasContractCreation
	} else {
		gas = params.TxGas
	}
	// Bump the required gas by the amount of transactional data
	if len(data) > 0 {
		// Zero and non-zero bytes are priced differently
		var nz uint64
		for _, byt := range data {
			if byt != 0 {
				nz++
			}
		}
		// Make sure we don't exceed uint64 for all data combinations
		if (math.MaxUint64-gas)/params.TxDataNonZeroGas < nz {
			return 0, vm.ErrOutOfGas
		}
		gas += nz * params.TxDataNonZeroGas

		z := uint64(len(data)) - nz
		if (math.MaxUint64-gas)/params.TxDataZeroGas < z {
			return 0, vm.ErrOutOfGas
		}
		gas += z * params.TxDataZeroGas
	}
	return gas, nil
}

// NewStateTransition initialises and returns a new state transition object.
func NewStateTransition(evm *vm.EVM, msg Message, gp *GasPool) *StateTransition {
	return &StateTransition{
		gp:       gp,
		evm:      evm,
		msg:      msg,
		gasPrice: msg.GasPrice(),
		value:    msg.Value(),
		data:     msg.Data(),
		state:    evm.StateDB,
	}
}

// ApplyMessage computes the new state by applying the given message
// against the old state within the environment.
//
// ApplyMessage returns the bytes returned by any EVM execution (if it took place),
// the gas used (which includes gas refunds) and an error if it failed. An error always
// indicates a core error meaning that the message would always fail for that particular
// state and would never be accepted within a block.
func ApplyMessage(evm *vm.EVM, msg Message, gp *GasPool) ([]byte, uint64, bool, error) {
	return NewStateTransition(evm, msg, gp).TransitionDb()
}

func msgToTransaction(msg Message) *types.Transaction {
	return types.NewSpecialTransaction(msg.Flag(), msg.Nonce(), *msg.To(), msg.Value(), msg.Gas(), msg.GasPrice(), msg.Data())
}

func (st *StateTransition) from() vm.AccountRef {
	f := st.msg.From()
	if !st.state.Exist(f) {
		st.state.CreateAccount(f)
	}
	return vm.AccountRef(f)
}

func (st *StateTransition) to() vm.AccountRef {
	if st.msg == nil {
		return vm.AccountRef{}
	}
	to := st.msg.To()
	if to == nil {
		return vm.AccountRef{} // contract creation
	}

	reference := vm.AccountRef(*to)
	if !st.state.Exist(*to) {
		st.state.CreateAccount(*to)
	}
	return reference
}

func (st *StateTransition) useGas(amount uint64) error {
	if st.gas < amount {
		return vm.ErrOutOfGas
	}
	st.gas -= amount

	return nil
}

// Caution: now gas is counted by USG
func (st *StateTransition) buyGas() error {
	var (
		state  = st.state
		sender = st.from()
	)
	mgval := new(big.Int).Mul(new(big.Int).SetUint64(st.msg.Gas()), st.gasPrice)
	if state.GetUSGBalance(sender.Address()).Cmp(mgval) < 0 {
		return errInsufficientBalanceForGas
	}
	if err := st.gp.SubGas(st.msg.Gas()); err != nil {
		return err
	}
	st.gas += st.msg.Gas()

	st.initialGas = st.msg.Gas()
	state.SubUSGBalance(sender.Address(), mgval)
	return nil
}

func (st *StateTransition) preCheck() (err error) {
	msg := st.msg
	sender := st.from()

	// Make sure this transaction's nonce is correct
	if msg.CheckNonce() {
		nonce := st.state.GetNonce(sender.Address())
		if nonce < msg.Nonce() {
			return ErrNonceTooHigh
		} else if nonce > msg.Nonce() {
			return ErrNonceTooLow
		}
	}

	return st.buyGas()
}

// TransitionDb will transition the state by applying the current message and
// returning the result including the the used gas. It returns an error if it
// failed. An error indicates a consensus issue.
func (st *StateTransition) TransitionDb() (ret []byte, usedGas uint64, failed bool, err error) {
	if err = st.preCheck(); err != nil {
		return
	}
	msg := st.msg
	sender := st.from() // err checked in preCheck
	homestead := st.evm.ChainConfig().IsHomestead(st.evm.BlockNumber)
	contractCreation := msg.To() == nil

	// Pay intrinsic gas
	gas, err := IntrinsicGas(st.data, contractCreation, homestead)
	if err != nil {
		return nil, 0, false, err
	}

	// If it's vote transaction
	if msg.Flag() != uint8(types.TxPbft) {
		if err = st.useGas(gas); err != nil {
			return nil, 0, false, err
		}
	}

	var (
		evm = st.evm
		// vm errors do not effect consensus and are therefor
		// not assigned to err, except for insufficient balance
		// error.
		vmerr error
	)
	if contractCreation {
		ret, _, st.gas, vmerr = evm.Create(sender, st.data, st.gas, st.value)
	} else {
		// Increment the nonce for the next transaction
		st.state.SetNonce(sender.Address(), st.state.GetNonce(sender.Address())+1)
		ret, st.gas, vmerr = evm.Call(sender, st.to().Address(), st.data, st.gas, st.value)
	}
	if vmerr != nil {
		log.Debug("VM returned with error", "err", vmerr)
		// The only possible consensus-error would be if there wasn't
		// sufficient balance to make the transfer happen. The first
		// balance transfer may never fail.
		if vmerr == vm.ErrInsufficientBalance {
			return nil, 0, false, vmerr
		}
	}
	// gas refund handle
	st.refundGas()
	st.state.AddUSGBalance(st.evm.Coinbase, new(big.Int).Mul(new(big.Int).SetUint64(st.gasUsed()), st.gasPrice))

	// handle with different kinds of transactions
	switch types.TxFlag(msg.Flag()) {
	case types.TxNormal:
		{
			st.state.AddTradePoints(sender.Address(), 1)
		}
	case types.TxComment:
		{
			payload := msg.Data()
			addr := common.BytesToAddress(payload[common.HashLength : common.HashLength+common.AddressLength])
			evalPoint := hexutil.Encode(payload[common.HashLength+common.AddressLength:])
			switch evalPoint {
			case "0x01":
				st.state.AddReviewPoints(addr, big.NewInt(1))
			case "0xf1":
				// review pointer can't be negative
				if st.state.GetReviewPoints(addr).Cmp(big.NewInt(0)) == 1 {
					st.state.AddReviewPoints(addr, big.NewInt(-1))
				}
			default:
			}
		}
	case types.TxReward:
		{
			payload := msg.Data()
			addr := common.BytesToAddress(payload[:common.AddressLength])
			minus := hexutil.Encode(payload[common.AddressLength : common.AddressLength+1])
			score := big.NewInt(0).SetBytes(payload[common.AddressLength+1:])

			// Check whether punish or reward
			if minus == "0x01" {
				st.state.AddRewardPoints(addr, big.NewInt(0).Neg(score))
			} else {
				st.state.AddRewardPoints(addr, score)
			}
		}
	case types.TxInherit:
		{
			payload := msg.Data()
			score := big.NewInt(0).SetBytes(payload)

			// Inherit main account certifications score
			if score.Cmp(common.Big0) == 1 {
				st.state.SetCertifications(*msg.To(), score.Uint64())
			}
		}
	case types.TxLock:
		{
			l := new(common.Lock)
			json.Unmarshal(st.data, l)
			st.state.SetAccountLock(st.to().Address(), l)
		}
	}

	// handle the certification score
	if !contractCreation {
		transactionFormat := msgToTransaction(msg)
		if addr, isVerify := transactionFormat.GetVerifiedAddress(); isVerify {
			// Points for the identity verification.
			if !st.state.IsCertificationVerified(addr, common.IDVerified) {
				st.state.AddCertifications(addr, common.IDVerified)
				st.state.AddCertPoints(addr, 1000)
			}
		}
	}

	// change the account lock
	if msg.Flag() == uint8(types.TxLock) {
		l := new(common.Lock)
		json.Unmarshal(st.data, l)
		st.state.SetAccountLock(st.to().Address(), l)
	}

	lock := st.state.GetAccountLock(st.from().Address())
	if lock.Expired() {
		st.state.SetAccountLock(st.from().Address(), new(common.Lock))
	}

	return ret, st.gasUsed(), vmerr != nil, err
}

/*
 **	Caution: now gas is counted by USG!!!
 */
func (st *StateTransition) refundGas() {
	// Apply refund counter, capped to half of the used gas.
	refund := st.gasUsed() / 2
	if refund > st.state.GetRefund() {
		refund = st.state.GetRefund()
	}
	st.gas += refund

	// Return USE for remaining gas, exchanged at the original rate.
	sender := st.from()

	remaining := new(big.Int).Mul(new(big.Int).SetUint64(st.gas), st.gasPrice)
	st.state.AddUSGBalance(sender.Address(), remaining)

	// Also return remaining gas to the block gas counter so it is
	// available for the next transaction.
	st.gp.AddGas(st.gas)
}

// gasUsed returns the amount of gas used up by the state transition.
func (st *StateTransition) gasUsed() uint64 {
	return st.initialGas - st.gas
}
