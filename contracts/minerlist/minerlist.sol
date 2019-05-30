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

pragma solidity ^0.4.20;

contract Committee {
    /// @notice Whether the msg.sender is committee or not.
    /// @return Whether the transfer was successful or not
    function IsOndutyCommittee(address _user) public view returns(bool);
}

contract Credit {
    /// @notice Whether the address is main account or not
    /// @return true or false
    function isMainAccount(address _user) public view returns(bool);
}

contract MinerList {

    address[] public Miner;

    // the mining ticket should be 50 USE
    uint256 ticket = 5e19;

    /// @notice Committee contract address
    address public CommitteeAddr = address("UmixYUgBHA9vJj47myQKn8uZAm4anNCcQBB");
    address public CreditAddr = address("UmixYUgBHA9vJj47myQKn8uZAm4an7zyYJ8");

    // missed block mining chance for miners
    uint256 constant public MisconductLimitsLevel1 = 150;
    uint256 constant public MisconductLimitsLevel2 = 300;
    uint256 constant public MisconductLimitsLevel3 = 450;
    mapping (address => uint256) public Misconducts;

    mapping (address => uint) public IsOnLine;
    mapping (address => uint) public PunishHeight;

    /// @notice Signle Mode, Multi Mode or Product Mode
    // 0: Product Mode
    // 1: Signle Mode
    uint public mode;

    /// @notice only miner can call
    modifier onlyMiner(address _miner) {
        bool isMiner = false;
        uint len=Miner.length;
        for (uint i = 0; i<len; i++){
            if(_miner == Miner[i]){
                isMiner = true;
                break;
            }
        }
        require (isMiner == true);
        _;
    }

    modifier onlyNotMiner(address _miner) {
        bool isMiner = false;
        uint len=Miner.length;
        for (uint i = 0; i<len; i++){
            if(_miner == Miner[i]){
                isMiner = true;
                break;
            }
        }
        require (isMiner == false);
        _;
    }

    modifier onlyCommittee(address _user) {
        require (Committee(CommitteeAddr).IsOndutyCommittee(_user) == true);
        _;
    }

    modifier onlyMainAccount(address _user) {
        if (mode == 0){
            require (Credit(CreditAddr).isMainAccount(_user) == true);
        }
        _;
    }

     modifier onlyNotPermanentPunishMiner(address _miner) {
        bool isPunishMiner = false;
        if (Misconducts[_miner] >= MisconductLimitsLevel3) {
            isPunishMiner = true;
        }
        require (isPunishMiner == false);
        _;
    }

    // calculate ticket should return to miners
    function dealTicket(address _miner)
    internal
    returns(uint256) {
        if (Misconducts[_miner] >= MisconductLimitsLevel3) {
            return ticket/2;
        }
        return ticket;
    }

    /// @notice set IsOnLine 1 , when miner.start()
    function setOnLine()
    public
    payable
    onlyMiner(msg.sender) {
        IsOnLine[msg.sender] = 1;
    }

    /// @notice set IsOnLine 0 , when miner.stop()
    function setOffLine()
    public
    payable
    onlyMiner(msg.sender) {
        IsOnLine[msg.sender] = 0;
    }

    /// @notice add miner
    function addMiner()
    public
    payable
    onlyNotMiner(msg.sender)
    onlyMainAccount(msg.sender)
    onlyNotPermanentPunishMiner(msg.sender)
    returns(bool) {
        require(msg.value >= ticket);
        if (msg.value > ticket) {
            uint256 refundFee = msg.value - ticket;
            msg.sender.transfer(refundFee);
        }
        Miner.push(msg.sender);
        IsOnLine[msg.sender] = 0;
        return true;
    }

    /// @dev del miner
    function delMinerBySelf()
    public
    payable
    onlyMiner(msg.sender)
    returns(bool) {
        uint len=Miner.length;
        for (uint i = 0; i<len; i++){
            if(msg.sender == Miner[i]){
                msg.sender.transfer(dealTicket(msg.sender));
                Miner[i] = Miner[len-1];
                Miner.length--;
                IsOnLine[msg.sender] = 0;
                break;
            }
        }
        return true;
    }

    /// @notice only committee can del miner
    /// Miners removed by the committee cannot be added to the miner list
    function delMinerByCommittee(address _miner)
    public
    payable
    onlyMiner(_miner)
    onlyCommittee(msg.sender)
    returns(bool) {
        uint len=Miner.length;
        for (uint i = 0; i<len; i++){
            if(_miner == Miner[i]){
                Miner[i] = Miner[len-1];
                Miner.length--;
                Misconducts[_miner] = MisconductLimitsLevel3;
                break;
            }
        }
        return true;
    }
}