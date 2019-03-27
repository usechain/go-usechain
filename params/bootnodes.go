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

package params

// MainnetBootnodes are the enode URLs of the P2P bootstrap nodes running on
// the main Usechain network.
var MainnetBootnodes = []string{
	"enode://c1d4fe20c8056ab1647df98a65412152ad0abc3039cee4bf0b758818897230965420e08240effc7c4a5ce417ecd2ba3465610d39018bea8bd28a3f7e010123e1@47.112.117.48:40404",
	"enode://41a7a04d8f4b7d0d5d3818f47079013ab7858542454ffb3df99ce0098e2e56a0bdbc8589b95b742d15f024722064ae5f8a9cfc35cd9fca60ee36296efad4970e@39.97.174.114:40404",
}

// TestnetBootnodes are the enode URLs of the P2P bootstrap nodes running on the
// test network.
var TestnetBootnodes = []string{}

// MoonetBootnodes are the enode URLs of the P2P bootstrap nodes running on the
// Moonet test network.
var MoonetBootnodes = []string{
	// Usechain Go moonet Bootnodes
	"enode://d48f0c9d8337ff59a827af8f7eca645efb2d2747cac5e2158f30ee840f7fff7bac9e10ac1626135e881c6a62dcf5dd2fb7b4bc6ca016cc6fa2a03d8bc50bc56f@[119.23.41.121]:40404",
}

// DiscoveryV5Bootnodes are the enode URLs of the P2P bootstrap nodes for the
// experimental RLPx v5 topic-discovery network.
var DiscoveryV5Bootnodes = []string{}
