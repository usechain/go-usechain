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

pragma solidity ^0.4.24;

contract MinerList {

    /// Indicator of miner
    uint256 public MinerNum;
    mapping (address => bool) public MinerAdded;

    modifier onlyMiner(address _miner) {
        require (MinerAdded[_miner] == true);
        _;
    }

    modifier onlyNotMiner(address _miner) {
        require (MinerAdded[_miner] == false);
        _;
    }

    ///change the owner
    function addMiner() public onlyNotMiner(msg.sender) returns(bool) {
        MinerAdded[msg.sender] = true;
        MinerNum++;
        return true;
    }

    ///del the owner
    function delMiner() public onlyMiner(msg.sender) returns(bool) {
        MinerAdded[msg.sender] = false;
        MinerNum--;
        return true;
    }

}

