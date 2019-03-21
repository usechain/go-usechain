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
package crypto

import (
	"testing"
)

func TestRSAKeypair(t *testing.T) {
	err := GenerateRSAKeypair()
	if err != nil {
		t.Fatal("Generate RSA key pair error")
	}
}

func TestRSA_Sign(t *testing.T) {
	message := "0x21a7325a75492db1ee86c1d2d22984b83f6082e5"
	sig, _ := RSA_Sign(message)

	res := RSA_Verify(message, sig)
	if res != true {
		t.Fatal("RSA sign message error")
	}
}

func TestRSA_V(t *testing.T) {
	message := "21a7325a75492db1ee86c1d2d22984b83f6082e5"
	sig, _ := RSA_Sign(message)
	res := RSA_Verify(message, sig)
	if res != true {
		t.Fatal("RSA signature not correct")
	}
}
