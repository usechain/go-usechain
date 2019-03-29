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
	"enode://650598d567def1fec835798b53234c0f8bdb6a902013fd3f7b00e5180a6b54934b0ee13abe2f3b933b981273db25bc188309e3b3053890af12da0416f8ec51c9@47.112.117.48:40404",
	"enode://ab0068a9fcaaee12d92b7b58b00361ad95a4986eaa17bceec93afad76100f3f17da41923d459215e6f5aa138e6a020c3e919d4c1f591b0f091029eae0c061118@39.97.174.114:40404",
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
