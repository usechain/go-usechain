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
	"enode://3b56784fb7c72963a78301de99cc51f79439f4acdb0473ef71d05d1f6ed4dc5eaa9d3413dcb2befc869ce5c9ec1c97125fe664eb45563607a41ee52437cfe497@39.105.102.190:30303",
	"enode://d53bb4ef27ca41ef397464ad41930d69f029001e9a75ef1d93a1694788f32093748a67c0b0b8d955827bc10dd55567c94b09be238578f8d2d90065f866467647@39.105.89.191:30303",
	"enode://b41005c04df7c0e64f5b731d1574b3eb19870b59370af3e99fb245c4b7d0720fb31694e34bae30387f24a5063c4002f5de473847f48b3a8927288634f549be7a@39.107.67.179:30303",
}

// DiscoveryV5Bootnodes are the enode URLs of the P2P bootstrap nodes for the
// experimental RLPx v5 topic-discovery network.
var DiscoveryV5Bootnodes = []string{}
