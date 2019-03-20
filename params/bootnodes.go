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
	"enode://1de6d73d3b7a288de8f571b8b48a89970053f26beeba787c9f36044cb2d1e89c0c94e802e579798efcc39c48a5e23a160e1ab9ae8f0b752725c7ab8ea40b3194@119.23.41.121:40404",
	"enode://f7fee44270a73ab44762598c0f7f2e0fc083d6eee5cbfbc365bd053d8c04886235c3a21fc4e5f3fb2a1deb257612e23c232b090bc2bf650c56fe839625d26cfa@47.112.117.48:40404",
	"enode://8613e162784e292803196f4a7c04c5ae0cfbb760acd3f1fa5a63222dcc0bc9d6450f8f9c113db622dcad3885849a9c9d9f23424bc94a6f15deb2643c6124a856@39.97.174.114:40404",
}

// DiscoveryV5Bootnodes are the enode URLs of the P2P bootstrap nodes for the
// experimental RLPx v5 topic-discovery network.
var DiscoveryV5Bootnodes = []string{}
