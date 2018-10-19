// Copyright 2018 The go-usechain Authors
// This file is part of the go-usechain library.
//
// The go-usechain library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-usechain library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-usechain library. If not, see <http://www.gnu.org/licenses/>.

pragma solidity ^ 0.4.24;

contract certStorage {

    // @notice Main Storage

    // @notice Committee
    uint public MAX_COMMITTEEMAN_COUNT = 15;
    uint public requirement = 0;
    uint public certIDCount = 1;
    uint public OneTimeAddrConfirmedLen = 0;
    uint public confirmedMainAddressLen = 0;
    uint public confirmedSubAddressLen = 0;
    uint public unConfirmedAddressLen  = 0;

    // @dev Committee
    struct committeeman {
        bool added;
        bool execution;
    }

    mapping (address => committeeman) public isCommittee;
    address[] public CMMTTEEs;

    mapping (address => string) public CommitteePublicKey;


    // struct certMsg {
    //     bool confirmed;
    //     uint addressType;
    //     string ringSig;
    //     string publicKey;
    //     string privateKey;
    //     string publicKeyMirror;
    // }

    struct certtoaddr {
        bool confirmed;
        address toAddress;
    }

    mapping (uint => certtoaddr) public CertToAddress;

    mapping (uint => mapping (address => bool)) public CommitteeConfirmations;

    // @notice Main storage
    struct oneTimeAddr {   // pos = 0/1/2/3
        bool confirmed;
        string caSign;
        string certMsg;
        string pubKey;
    }

    mapping (address => oneTimeAddr) public OneTimeAddr;
    address[] public OneTimeAddrConfirmed;


    // @dev addr type
enum addrType {
        main,
            sub
    }

    struct addressList {
        bool added;
        bool confirmed;
        uint8 addressType;
        string ringSig;
        string pubSKey;
        string publicKeyMirror;
    }

    mapping (address => addressList) public CertificateAddr;


    address[] public confirmedMainAddress;
    address[] public confirmedSubAddress;
    uint[] public unConfirmedAddress;

}

// @notice MultiSig contract
contract MultiSig is certStorage {

    // @notice events
    event Confirmation(address indexed confirmed, uint indexed submitIndex, bool indexed added);
    event Submission(address indexed sender, uint indexed submitIndex,  bool indexed added);
    event Execution(uint indexed submitIndex);
    event ExecutionFailure(uint indexed submitIndex);
    event CommitteemanAddition(address indexed Committeeman);
    event CommitteemanRemoval(address indexed Committeeman);

    // @notice modifier
    modifier committeeDoesExist (address _addr) {
        require (isCommittee[_addr].added);
        _;
    }

    modifier committeeDoesNotExist(address _addr) {
        require (!isCommittee[_addr].added);
        _;
    }

    modifier addressNotAdded (address _addr) {
        require (!CertificateAddr[_addr].added);
        _;
    }

    /*
    modifier certConfirmed (uint _certid) {
        require (CertToAddress[_certid].confirmed);
        _;
    }*/

    modifier certNotConfirmed (uint _certid) {
        require (!CertToAddress[_certid].confirmed);
        _;
    }

    // @notice change requirement
    function updateRequire() internal {
        requirement = CMMTTEEs.length / 2;
    }

    function addCommittee(address _newPending, string _publicKey)
    committeeDoesExist(msg.sender)
    public
    returns (bool)
    {
        require (!isCommittee[_newPending].added);
        isCommittee[_newPending].added = true;
        CommitteePublicKey[_newPending] = _publicKey;
        CMMTTEEs.push(_newPending);
        require(CMMTTEEs.length <= MAX_COMMITTEEMAN_COUNT);
        updateRequire();
    }

    function removeCommittee(address _newPending)
    committeeDoesExist(msg.sender)
    public
    returns (bool)
    {
        require (isCommittee[_newPending].added);
        for (uint i = 0; i < CMMTTEEs.length; i++) {
        if (CMMTTEEs[i] == _newPending) {
            CMMTTEEs[i] = CMMTTEEs[CMMTTEEs.length - 1];
            break;
        }
    }
        isCommittee[_newPending].added = false;
        CMMTTEEs.length -= 1;
        updateRequire();
    }

    //-----------multiSig

    function summitCert(uint8 _addressType, string _ringSig, string _pub_S_Key, string _publicKeyMirror)

    public
    returns (uint _certID)
    {
        _certID = certIDCount;
        CertificateAddr[msg.sender].added = true;
        CertificateAddr[msg.sender].addressType = _addressType;
        CertificateAddr[msg.sender].ringSig = _ringSig;
        CertificateAddr[msg.sender].pubSKey = _pub_S_Key;
        CertificateAddr[msg.sender].publicKeyMirror = _publicKeyMirror;
        CertToAddress[_certID].toAddress = msg.sender;
        certIDCount += 1;
        unConfirmedAddress.push(_certID);
        unConfirmedAddressLen = unConfirmedAddress.length;
        emit Submission(msg.sender, _certID, true);
    }

    function confirmCert(uint _certID, bool _confirm)
    committeeDoesExist(msg.sender)
    certNotConfirmed(_certID)
    public
    {
        require (_certID != 0);
        if (_confirm == false) {
            CommitteeConfirmations[_certID][msg.sender] = false;
            delete CertificateAddr[CertToAddress[_certID].toAddress];
            delete CertToAddress[_certID];
        }
        CommitteeConfirmations[_certID][msg.sender] = true;
        emit Confirmation(msg.sender, _certID, true);
        executionCert(_certID);
    }

    function executionCert(uint _certID)
    internal
    {
        if(isConfirmed(_certID)) {
            address _confirmedAddr = CertToAddress[_certID].toAddress;
            CertToAddress[_certID].confirmed = true;
            CertificateAddr[_confirmedAddr].confirmed = true;
            addToConfirmList(_confirmedAddr);
            for (uint i= 0; i < unConfirmedAddressLen; i++) {
                if (unConfirmedAddress[i] == _certID) {
                    unConfirmedAddress[i] = unConfirmedAddress[unConfirmedAddressLen - 1];
                    unConfirmedAddress.length -= 1;
                    unConfirmedAddressLen = unConfirmedAddress.length;
                }
            }
        }
    }

    function isConfirmed (uint _certID)
    internal
    view
    returns (bool)
    {
        uint8 _count = 0;
        for (uint8 i = 0; i < CMMTTEEs.length; i++) {
        if (CommitteeConfirmations[_certID][CMMTTEEs[i]])
            _count += 1;
        if (_count >= requirement)
            return true;
    }
        return false;
    }

    function addToConfirmList(address _confirmedAddr)
    internal
    returns (bool)
    {
        if (CertificateAddr[_confirmedAddr].addressType == uint(addrType.main)) {
            confirmedMainAddress.push(_confirmedAddr);
            confirmedMainAddressLen = confirmedMainAddress.length;
            return true;
        }
        if (CertificateAddr[_confirmedAddr].addressType == uint(addrType.sub)) {
            confirmedSubAddress.push(_confirmedAddr);
            confirmedSubAddressLen = confirmedSubAddress.length;
            return true;
        }
    }

}

// contract

// @dev Main to do work
contract Main is MultiSig {
    // @notice certificate contract infos
    string constant public contractName = "Usechain Certificate Smart Contract.";
    string constant public contractVersion = "Ver 0.1";

    // @notice modifier
    modifier oneTimeAddrNotAdded(address _addr) {
        require(!OneTimeAddr[_addr].confirmed);
        _;
    }

    // @notice constructor
    constructor(string _createrPubKey) public {
        CMMTTEEs.push(msg.sender);
        CommitteePublicKey[msg.sender] = _createrPubKey;
        isCommittee[msg.sender].added = true;
    }

    function storeOneTimeAddress(string _pubkey, string _sign, string _CA)
    oneTimeAddrNotAdded(msg.sender)
    public
    returns (bool)
    {
        OneTimeAddr[msg.sender].confirmed = true;
        OneTimeAddr[msg.sender].caSign = _sign;
        OneTimeAddr[msg.sender].certMsg = _CA;
        OneTimeAddr[msg.sender].pubKey = _pubkey;
        OneTimeAddrConfirmed.push(msg.sender);
        OneTimeAddrConfirmedLen = OneTimeAddrConfirmed.length;
        return true;
    }


    // @dev check that one time addr confirmed
    function checkOneTimeAddrAdded(address _addr) public view returns (bool) {
        return OneTimeAddr[_addr].confirmed;
    }


    // @dev check that the main/sub address has been confirmed
    function checkAddrConfirmed(address _addr) public view returns (bool) {
        require (CertificateAddr[_addr].added == true);
        return CertificateAddr[_addr].confirmed;
    }

    // @dev store main user certificate
    function storeMainUserCert(string _ringSig, string _pub_S_Key, string _publicKeyMirror)
    public
    returns (uint, bool)
    {
        uint certid = summitCert(uint8(addrType.main), _ringSig, _pub_S_Key, _publicKeyMirror);
        if (certid != 0) {
            return (certid, true);
        }

    }

    // @dev store sub user certificate
    function storeSubUserCert(string _ringSig, string _pub_S_Key, string _publicKeyMirror)
    public
    returns (uint, bool)
    {
        uint certid = summitCert(uint8(addrType.sub), _ringSig, _pub_S_Key, _publicKeyMirror);
        if (certid != 0) {
            return (certid, true);
        }

    }
    /*
    function storeUserCert(uint8 addrtype, string _ringSig, string _pub_S_Key, string _publicKeyMirror)
        addressNotAdded(msg.sender)
        public
        returns (bool)
    {
        if (addrtype == 0)
            summitCert(uint8(addrType.main), _ringSig, _pub_S_Key, _publicKeyMirror);
        else
            summitCert(uint8(addrType.sub), _ringSig, _pub_S_Key, _publicKeyMirror);
        return true;
    }*/

}
