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
	"enode://c47ef3fafe4619b4c454ad62fd23761050c0f7d6a68bec2d492c79a1eb6d83ebc6089a0c14c9664f2267141bf0694a7f623954cf13a078dd3d8b2851ed5d3f96@[39.97.174.114]:40404",
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
