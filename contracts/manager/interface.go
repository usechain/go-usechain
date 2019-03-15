package manager

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/usechain/go-usechain/common"
	"github.com/usechain/go-usechain/core/state"
	"github.com/usechain/go-usechain/crypto/sha3"
	"math/big"
	"strings"
)

const (
	ManagerContract = "0xfffffffffffffffffffffffffffffffff0000003"
	ABI             = "[{\"constant\": false,\"inputs\": [{\"name\": \"_asymPubkey\",\"type\": \"string\"}],\"name\": \"confirmAndKeyUpload\",\"outputs\": [],\"payable\": false,\"stateMutability\": \"nonpayable\",\"type\": \"function\"},{\"constant\": false,\"inputs\": [{\"name\": \"_pubkey\",\"type\": \"string\"}],\"name\": \"confirmCommitteePubkey\",\"outputs\": [],\"payable\": false,\"stateMutability\": \"nonpayable\",\"type\": \"function\"},{\"constant\": false,\"inputs\": [],\"name\": \"confirmVoting\",\"outputs\": [],\"payable\": false,\"stateMutability\": \"nonpayable\",\"type\": \"function\"},{\"constant\": false,\"inputs\": [{\"name\": \"_flag\",\"type\": \"bool\"}],\"name\": \"controlVote\",\"outputs\": [],\"payable\": false,\"stateMutability\": \"nonpayable\",\"type\": \"function\"},{\"constant\": false,\"inputs\": [{\"name\": \"_candidate\",\"type\": \"address[]\"}],\"name\": \"initial\",\"outputs\": [],\"payable\": false,\"stateMutability\": \"nonpayable\",\"type\": \"function\"},{\"constant\": false,\"inputs\": [{\"name\": \"_pubkey\",\"type\": \"string\"}],\"name\": \"uploadCommitteePubkey\",\"outputs\": [],\"payable\": false,\"stateMutability\": \"nonpayable\",\"type\": \"function\"},{\"constant\": false,\"inputs\": [{\"name\": \"_candidate\",\"type\": \"address\"}],\"name\": \"vote\",\"outputs\": [{\"name\": \"\",\"type\": \"bool\"}],\"payable\": false,\"stateMutability\": \"nonpayable\",\"type\": \"function\"},{\"constant\": true,\"inputs\": [{\"name\": \"\",\"type\": \"uint256\"}],\"name\": \"committeeOnDuty\",\"outputs\": [{\"name\": \"\",\"type\": \"address\"}],\"payable\": false,\"stateMutability\": \"view\",\"type\": \"function\"},{\"constant\": true,\"inputs\": [],\"name\": \"committeeOnDutyPublicKey\",\"outputs\": [{\"name\": \"\",\"type\": \"string\"}],\"payable\": false,\"stateMutability\": \"view\",\"type\": \"function\"},{\"constant\": true,\"inputs\": [],\"name\": \"Election_cycle\",\"outputs\": [{\"name\": \"\",\"type\": \"uint256\"}],\"payable\": false,\"stateMutability\": \"view\",\"type\": \"function\"},{\"constant\": true,\"inputs\": [],\"name\": \"Election_duration\",\"outputs\": [{\"name\": \"\",\"type\": \"uint256\"}],\"payable\": false,\"stateMutability\": \"view\",\"type\": \"function\"},{\"constant\": true,\"inputs\": [],\"name\": \"getBlockNumber\",\"outputs\": [{\"name\": \"\",\"type\": \"uint256\"}],\"payable\": false,\"stateMutability\": \"view\",\"type\": \"function\"},{\"constant\": true,\"inputs\": [{\"name\": \"_index\",\"type\": \"uint256\"}],\"name\": \"getCandidate\",\"outputs\": [{\"name\": \"\",\"type\": \"address\"}],\"payable\": false,\"stateMutability\": \"view\",\"type\": \"function\"},{\"constant\": true,\"inputs\": [],\"name\": \"getCandidateLen\",\"outputs\": [{\"name\": \"\",\"type\": \"uint256\"}],\"payable\": false,\"stateMutability\": \"view\",\"type\": \"function\"},{\"constant\": true,\"inputs\": [{\"name\": \"_index\",\"type\": \"uint256\"}],\"name\": \"getCommittee\",\"outputs\": [{\"name\": \"\",\"type\": \"address\"}],\"payable\": false,\"stateMutability\": \"view\",\"type\": \"function\"},{\"constant\": true,\"inputs\": [{\"name\": \"index\",\"type\": \"uint256\"}],\"name\": \"getCommitteeAsymkey\",\"outputs\": [{\"name\": \"\",\"type\": \"string\"}],\"payable\": false,\"stateMutability\": \"view\",\"type\": \"function\"},{\"constant\": true,\"inputs\": [],\"name\": \"getCommitteeConfirmStat\",\"outputs\": [{\"name\": \"\",\"type\": \"bool\"}],\"payable\": false,\"stateMutability\": \"view\",\"type\": \"function\"},{\"constant\": true,\"inputs\": [],\"name\": \"getCommitteeIndex\",\"outputs\": [{\"name\": \"\",\"type\": \"int256\"}],\"payable\": false,\"stateMutability\": \"view\",\"type\": \"function\"},{\"constant\": true,\"inputs\": [],\"name\": \"getCommitteePubkey\",\"outputs\": [{\"name\": \"\",\"type\": \"string\"}],\"payable\": false,\"stateMutability\": \"view\",\"type\": \"function\"},{\"constant\": true,\"inputs\": [{\"name\": \"_candidate\",\"type\": \"address\"}],\"name\": \"getVotes\",\"outputs\": [{\"name\": \"\",\"type\": \"uint256\"}],\"payable\": false,\"stateMutability\": \"view\",\"type\": \"function\"},{\"constant\": true,\"inputs\": [],\"name\": \"IsCommittee\",\"outputs\": [{\"name\": \"\",\"type\": \"bool\"}],\"payable\": false,\"stateMutability\": \"view\",\"type\": \"function\"},{\"constant\": true,\"inputs\": [],\"name\": \"isEntireConfirmed\",\"outputs\": [{\"name\": \"\",\"type\": \"bool\"}],\"payable\": false,\"stateMutability\": \"view\",\"type\": \"function\"},{\"constant\": true,\"inputs\": [{\"name\": \"_user\",\"type\": \"address\"}],\"name\": \"IsOndutyCommittee\",\"outputs\": [{\"name\": \"\",\"type\": \"bool\"}],\"payable\": false,\"stateMutability\": \"view\",\"type\": \"function\"},{\"constant\": true,\"inputs\": [],\"name\": \"MAX_COMMITTEEMAN_COUNT\",\"outputs\": [{\"name\": \"\",\"type\": \"uint256\"}],\"payable\": false,\"stateMutability\": \"view\",\"type\": \"function\"},{\"constant\": true,\"inputs\": [],\"name\": \"mode\",\"outputs\": [{\"name\": \"\",\"type\": \"uint256\"}],\"payable\": false,\"stateMutability\": \"view\",\"type\": \"function\"},{\"constant\": true,\"inputs\": [],\"name\": \"Requirement\",\"outputs\": [{\"name\": \"\",\"type\": \"uint256\"}],\"payable\": false,\"stateMutability\": \"view\",\"type\": \"function\"},{\"constant\": true,\"inputs\": [{\"name\": \"\",\"type\": \"uint256\"}],\"name\": \"rounds\",\"outputs\": [{\"name\": \"selected\",\"type\": \"bool\"},{\"name\": \"committeePublicKey\",\"type\": \"string\"},{\"name\": \"committeePublicKey_candidate\",\"type\": \"string\"},{\"name\": \"confirmCount\",\"type\": \"uint256\"}],\"payable\": false,\"stateMutability\": \"view\",\"type\": \"function\"},{\"constant\": true,\"inputs\": [],\"name\": \"vote_enabled\",\"outputs\": [{\"name\": \"\",\"type\": \"bool\"}],\"payable\": false,\"stateMutability\": \"view\",\"type\": \"function\"}]"
)

var (
	SingleMode = big.NewInt(1)
	NormalMode = big.NewInt(0)
)

// Get the committee max count based on state db reader
// Normal mode 0: 5 committees
// Single mode 1: 1 committees
func GetCommitteeCount(statedb *state.StateDB) int32 {
	// detect the contract running mode
	res := statedb.GetState(common.HexToAddress(ManagerContract), common.BigToHash(common.Big0))
	// if running in single mode, just one committee
	if res.Big().Cmp(SingleMode) == 0 {
		return 1
	}
	// if normal mode, should be 5 committees
	return 5
}

//Check the address whether be a committee based on state db reader
func IsCommittee(statedb *state.StateDB, addr common.Address) bool {
	// detect the contract running mode
	res := statedb.GetState(common.HexToAddress(ManagerContract), common.BigToHash(common.Big0))

	// if running in single mode, anyone could be committee
	if res.Big().Cmp(common.Big1) == 0 {
		return true
	}
	// if normal mode, need strict check based on state db
	// the committeeOnDuty Array key index start from 2
	///TODO:change the committeeOnDuty to map struct for decline db queries
	for i := int64(0); i < int64(common.MaxCommitteemanCount); i++ {
		res := statedb.GetState(common.HexToAddress(ManagerContract), common.BigToHash(big.NewInt(i+2)))
		if strings.EqualFold(addr.Hash().String(), res.String()) {
			return true
		}
	}
	return false
}

// read the committee public key from contract
func GetCommitteePublicKey(statedb *state.StateDB) (res string, err error) {
	//read the committee public key length
	resIndex := statedb.GetState(common.HexToAddress(ManagerContract), common.BigToHash(big.NewInt(7)))

	// get data from the contract statedb
	eachPublicKeyLen := resIndex.Big().Int64()
	if eachPublicKeyLen == 0 {
		return "", fmt.Errorf("the committee public key haven't been load yet")
	}
	if eachPublicKeyLen < common.HashLength {
		return hex.EncodeToString(resIndex[:eachPublicKeyLen]), nil
	}
	forLen := eachPublicKeyLen / (int64(common.HashLength) * 2)

	// init query data hash
	newKeyIndex := CalculateStateDbIndex(big.NewInt(7))
	var buff bytes.Buffer
	for j := int64(0); j <= forLen; j++ {
		newKeyIndexString := common.IncreaseHexByNum(newKeyIndex, j)
		result := statedb.GetState(common.HexToAddress(ManagerContract), common.HexToHash(newKeyIndexString))
		buff.Write(result[:])
		//res += BytesToString(result[:])
	}
	res += buff.String()[:eachPublicKeyLen/2]
	return res, nil
}

// calculate the statedb index from key and parameter
func CalculateStateDbIndex(key *big.Int) []byte {
	web3key := common.BigToHash(key).Bytes()
	hash := sha3.NewKeccak256()
	var keyIndex []byte
	hash.Write(web3key)
	keyIndex = hash.Sum(keyIndex)
	return keyIndex
}
