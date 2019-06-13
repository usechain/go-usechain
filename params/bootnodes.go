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
	"enode://c462af0b916f64b2a0447880122eeb853d97c07787a29998251fe7755757079abe92742826e0cebb1450dcaf08a965db1c5bc47e9745cfdf92fcc2af156e4943@[39.97.174.114]:40404",
	"enode://00faa4fe1c7e23d6975ec3e1bf38e5267783702599704f5ca01bee7841243f445cb8e767fe06044d3df6f0d5d10a0f0abfa67a06abba39bb236a19f3395aa212@[47.112.117.48]:40404",
}

// TestnetBootnodes are the enode URLs of the P2P bootstrap nodes running on the
// test network.
var TestnetBootnodes = []string{}

// MoonetBootnodes are the enode URLs of the P2P bootstrap nodes running on the
// Moonet test network.
var MoonetBootnodes = []string{
	// Usechain Go moonet Bootnodes
	"enode://f8c5976c23505d18cdfcf4c689a95f762fc3a54de22f95cc416866c213da67ea6760d9d4075ba49f53d8b2c64c2c39f01b67859d2b2fda47f07cccb9563afb6b@[119.23.41.121]:40404",
}

// DiscoveryV5Bootnodes are the enode URLs of the P2P bootstrap nodes for the
// experimental RLPx v5 topic-discovery network.
var DiscoveryV5Bootnodes = []string{}
