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

package sssa

import (
	"fmt"
	"time"
	"github.com/gsocket"
)

type demoClient struct{}

func (client *demoClient) OnConnect(c *gsocket.Connection) {
	fmt.Printf("CONNECTED: %s\n", c.RemoteAddr())
}

func (client *demoClient) OnDisconnect(c *gsocket.Connection) {
	fmt.Printf("DISCONNECTED: %s\n", c.RemoteAddr())
}

func (client *demoClient) OnRecv(c *gsocket.Connection, data []byte) {
	//fmt.Printf("DATA RECVED: %s %d - %v\n", c.RemoteAddr(), len(data), data)
}

func (client *demoClient) OnError(c *gsocket.Connection, err error) {
	fmt.Printf("ERROR: %s - %s\n", c.RemoteAddr(), err.Error())
}

func SendMsg(port uint16, msg []byte) (string, error) {
	demoClient := &demoClient{}

	client := gsocket.CreateTCPClient(demoClient.OnConnect, demoClient.OnDisconnect, demoClient.OnRecv, demoClient.OnError)

	err := client.Connect("127.0.0.1", port)
	if err != nil {
		fmt.Printf("Connect Server Error: %s\n", err.Error())
		return "", err
	}
	fmt.Printf("Connect Server %s Success\n", client.RemoteAddr())
	client.Send(msg)
	time.Sleep(1000000)
	client.Close()
	return  "okay", nil
}


