// Copyright 2015 The go-ethereum Authors
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
	"errors"
	"math"
	"math/big"

	"github.com/usechain/go-usechain/common"
	"github.com/usechain/go-usechain/consensus"
	"github.com/usechain/go-usechain/consensus/misc"
	"github.com/usechain/go-usechain/contracts/manager"
	"github.com/usechain/go-usechain/core/state"
	"github.com/usechain/go-usechain/core/types"
	"github.com/usechain/go-usechain/core/vm"
	"github.com/usechain/go-usechain/crypto"
	"github.com/usechain/go-usechain/params"
)

// StateProcessor is a basic Processor, which takes care of transitioning
// state from one point to another.
//
// StateProcessor implements Processor.
type StateProcessor struct {
	config *params.ChainConfig // Chain configuration options
	bc     *BlockChain         // Canonical block chain
	engine consensus.Engine    // Consensus engine used for block rewards
}

// NewStateProcessor initialises a new StateProcessor.
func NewStateProcessor(config *params.ChainConfig, bc *BlockChain, engine consensus.Engine) *StateProcessor {
	return &StateProcessor{
		config: config,
		bc:     bc,
		engine: engine,
	}
}

// Process processes the state changes according to the Ethereum rules by running
// the transaction messages using the statedb and applying any rewards to both
// the processor (coinbase) and any included uncles.
//
// Process returns the receipts and logs accumulated during the process and
// returns the amount of gas that was used in the process. If any of the
// transactions failed to execute due to insufficient gas it will return an error.
func (p *StateProcessor) Process(block *types.Block, statedb *state.StateDB, cfg vm.Config) (types.Receipts, []*types.Log, uint64, error) {
	var (
		receipts types.Receipts
		usedGas  = new(uint64)
		header   = block.Header()
		allLogs  []*types.Log
		gp       = new(GasPool).AddGas(block.GasLimit())
	)
	// Mutate the the block and state according to any hard-fork specs
	if p.config.DAOForkSupport && p.config.DAOForkBlock != nil && p.config.DAOForkBlock.Cmp(block.Number()) == 0 {
		misc.ApplyDAOHardFork(statedb)
	}

	// Iterate over and process the individual transactions
	p.bc.committeeCnt = manager.GetCommitteeCount(statedb)
	if header.IsCheckPoint.Int64() == 1 {
		txs := block.Transactions()
		if float64(txs.Len()) < math.Ceil(float64(p.bc.committeeCnt)*2/3) {
			err := errors.New("checkpoint block should contain more than three-seconds voter")
			return nil, nil, 0, err
		}
		hash := common.BytesToHash(txs[0].Data()[:common.HashLength])
		height := common.BytesToUint64(txs[0].Data()[common.HashLength : common.HashLength+8])
		index := common.BytesToUint64(txs[0].Data()[common.HashLength+8:])
		count := 1
		for i := 1; i < txs.Len(); i++ {
			if hash != common.BytesToHash(txs[i].Data()[:common.HashLength]) {
				err := errors.New("checkpoint block should contain same hash in txs")
				return nil, nil, 0, err
			}
			if height != common.BytesToUint64(txs[i].Data()[common.HashLength:common.HashLength+8]) {
				err := errors.New("checkpoint block should contain same height in txs")
				return nil, nil, 0, err
			}
			if index != common.BytesToUint64(txs[i].Data()[common.HashLength+8:]) {
				err := errors.New("checkpoint block should contain same index in txs")
				return nil, nil, 0, err
			}
			count++
		}
		if float64(count) < math.Ceil(float64(p.bc.committeeCnt)*2/3) {
			err := errors.New("checkpoint block should contain more than three-seconds voter with same hashes")
			return nil, nil, 0, err
		}
	}

	// check the txs
	for i, tx := range block.Transactions() {
		if header.IsCheckPoint.Int64() == 1 && tx.Flag() == 0 {
			err := errors.New("checkpoint block can't package common transactions")
			return nil, nil, 0, err
		}
		if header.IsCheckPoint.Int64() == 0 && tx.Flag() == 1 {
			err := errors.New("common block can't package checkpoint transactions")
			return nil, nil, 0, err
		}

		///TODO:all transaction should be identified by Tx.flag, with switch
		msg, err2 := tx.AsMessage(types.MakeSigner(p.config, header.Number))
		if err2 != nil {
			return nil, nil, 0, err2
		}
		sender := msg.From()
		if tx.Flag() == 1 {
			err := ValidatePbftTx(statedb, big.NewInt(block.Number().Int64()-1), false, 0, tx, common.Address(sender))
			if err != nil {
				return nil, nil, 0, err
			}
		} else if statedb.GetAccountLock(sender).Permission == 1 {
			err := errors.New("transaction send from locked account")
			return nil, nil, 0, err

		} else if tx.IsRegisterTransaction() {
			chainid := p.config.ChainId
			err := tx.CheckCertLegality(common.Address(sender), chainid)
			if err != nil {
				return nil, nil, 0, err
			}
		}

		statedb.Prepare(tx.Hash(), block.Hash(), i)
		receipt, _, err := ApplyTransaction(p.config, p.bc, nil, gp, statedb, header, tx, usedGas, cfg)
		if err != nil {
			return nil, nil, 0, err
		}
		receipts = append(receipts, receipt)
		allLogs = append(allLogs, receipt.Logs...)
	}
	// Finalize the block, applying any consensus engine specific extras (e.g. block rewards)
	p.engine.Finalize(p.bc, header, statedb, block.Transactions(), block.Uncles(), receipts)

	return receipts, allLogs, *usedGas, nil
}

// ApplyTransaction attempts to apply a transaction to the given state database
// and uses the input parameters for its environment. It returns the receipt
// for the transaction, gas used and an error if the transaction failed,
// indicating the block was invalid.
func ApplyTransaction(config *params.ChainConfig, bc *BlockChain, author *common.Address, gp *GasPool, statedb *state.StateDB, header *types.Header, tx *types.Transaction, usedGas *uint64, cfg vm.Config) (*types.Receipt, uint64, error) {
	msg, err := tx.AsMessage(types.MakeSigner(config, header.Number))
	if err != nil {
		return nil, 0, err
	}
	// Create a new context to be used in the EVM environment
	context := NewEVMContext(msg, header, bc, author)
	// Create a new environment which holds all relevant information
	// about the transaction and calling mechanisms.
	vmenv := vm.NewEVM(context, statedb, config, cfg)
	// Apply the transaction to the current state (included in the env)
	_, gas, failed, err := ApplyMessage(vmenv, msg, gp)
	if err != nil {
		return nil, 0, err
	}
	// Update the state with pending changes
	var root []byte
	if config.IsByzantium(header.Number) {
		statedb.Finalise(true)
	} else {
		root = statedb.IntermediateRoot(config.IsEIP158(header.Number)).Bytes()
	}
	*usedGas += gas

	// Create a new receipt for the transaction, storing the intermediate root and gas used by the tx
	// based on the eip phase, we're passing wether the root touch-delete accounts.
	receipt := types.NewReceipt(root, failed, *usedGas)
	receipt.TxHash = tx.Hash()
	receipt.GasUsed = gas
	// if the transaction created a contract, store the creation address in the receipt.
	if msg.To() == nil {
		receipt.ContractAddress = crypto.CreateAddress(vmenv.Context.Origin, tx.Nonce())
	}
	// Set the receipt logs and create a bloom for filtering
	receipt.Logs = statedb.GetLogs(tx.Hash())
	receipt.Bloom = types.CreateBloom(types.Receipts{receipt})

	return receipt, gas, err
}
