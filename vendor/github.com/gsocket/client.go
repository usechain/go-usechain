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

package gsocket

import (
	"log"
)

type demoClient struct{}

func (client *demoClient) OnConnect(c *Connection) {
	log.Printf("CONNECTED: %s\n", c.RemoteAddr())
}

func (client *demoClient) OnDisconnect(c *Connection) {
	log.Printf("DISCONNECTED: %s\n", c.RemoteAddr())
}

func (client *demoClient) OnRecv(c *Connection, data []byte) {
	log.Printf("DATA RECVED: %s %d - %v\n", c.RemoteAddr(), len(data), data)
}

func (client *demoClient) OnError(c *Connection, err error) {
	log.Printf("ERROR: %s - %s\n", c.RemoteAddr(), err.Error())
}

func client() {
	demoClient := &demoClient{}

	client := CreateTCPClient(demoClient.OnConnect, demoClient.OnDisconnect, demoClient.OnRecv, demoClient.OnError)

	err := client.Connect("127.0.0.1", 9001)
	if err != nil {
		log.Printf("Coneect Server Error: %s\n", err.Error())
		return
	}

	log.Printf("Connect Server %s Success\n", client.RemoteAddr())

	client.Send([]byte("Hello World!!!"))

	pause()
	client.Close()
}

