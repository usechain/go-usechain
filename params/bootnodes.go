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

package params

// MainnetBootnodes are the enode URLs of the P2P bootstrap nodes running on
// the main Usechain network.
var MainnetBootnodes = []string{}

// TestnetBootnodes are the enode URLs of the P2P bootstrap nodes running on the
// test network.
var TestnetBootnodes = []string{}

// MoonetBootnodes are the enode URLs of the P2P bootstrap nodes running on the
// Moonet test network.
var MoonetBootnodes = []string{
	// Usechain Go moonet Bootnodes
	"enode://ca421825c1e33c9dfa2a2dfc2b598fd2f2fefd4cafe59d1e75eb5c2cdb8340d240fb33ce5139491813b0ec7a701dd1cfeb5bd8e49b73d94da899d832a8b56610@119.23.41.121:40404",
}

// DiscoveryV5Bootnodes are the enode URLs of the P2P bootstrap nodes for the
// experimental RLPx v5 topic-discovery network.
var DiscoveryV5Bootnodes = []string{}
