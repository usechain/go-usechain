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

pragma solidity >=0.5.2 <0.6.0;

contract Committee {
    /// @notice Whether the msg.sender is committee or not.
    /// @return Whether the transfer was successful or not
    function IsOndutyCommittee(address _user) public view returns(bool success);
}

contract Credit {
    /// @notice Whether the address is main account or not
    /// @return true or false
    function isMainAccount(address _user) public view returns (bool);
}

contract MinerList {

    address[] public Miner;

    uint256 ticket = 1 ether;

    /// @notice Committee contract address
    address public CommitteeAddr = address(0xffFFFfFFffFfffffFffFFfFFFFFFFFFff0000003);
    address public CreditAddr = address(0xfFffffffffFfFFffFffFfFFfFfffFfFff0000001);

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
        require (Credit(CreditAddr).isMainAccount(_user) == true);
        _;
    }

    /// @notice add miner
    function addMiner()
        public
        payable
        onlyNotMiner(msg.sender)
        onlyMainAccount(msg.sender)
        returns(bool) {
        require(msg.value >= ticket);
        if (msg.value > ticket) {
            uint256 refundFee = msg.value - ticket;
            msg.sender.transfer(refundFee);
        }
        Miner.push(msg.sender);
        return true;
    }

    /// @dev del miner
    function delMinerBySelf() public payable onlyMiner(msg.sender) returns(bool) {
        uint len=Miner.length;
        for (uint i = 0; i<len; i++){
            if(msg.sender == Miner[i]){
                msg.sender.transfer(ticket);
                Miner[i] = Miner[len-1];
                Miner.length--;
                break;
            }
        }
        return true;
    }

    /// @notice only committee can del miner
    function delMinerByCommittee(address payable _miner) public payable onlyMiner(_miner) onlyCommittee(msg.sender) returns(bool) {
        uint len=Miner.length;
        for (uint i = 0; i<len; i++){
            if(_miner == Miner[i]){
                _miner.transfer(ticket);
                Miner[i] = Miner[len-1];
                Miner.length--;
                break;
            }
        }
        return true;
    }
}
