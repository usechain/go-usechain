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

package committee

import (
	"fmt"
	"testing"
	"github.com/gsocket"
	"github.com/usechain/go-usechain/commitee/sssa"
	"time"
	"flag"
)
var ServerID uint16
var ServerPort uint16

type demoServer struct{}

// OnConnect 客户端连接事件
func (server demoServer) OnConnect(c *gsocket.Connection) {
	fmt.Printf("CONNECTED: %s\n", c.RemoteAddr())
}

// OnDisconnect 客户端断开连接事件
func (server demoServer) OnDisconnect(c *gsocket.Connection) {
	fmt.Printf("DISCONNECTED: %s\n", c.RemoteAddr())
}

// OnRecv 收到客户端发来的数据
func (server demoServer) OnRecv(c *gsocket.Connection, data []byte) {
	fmt.Printf("DATA RECVED: %s %d - %s\n", c.RemoteAddr(), len(data), data)
	sssa.DistributeMsg(data, ServerID, ServerPort)
}

// OnError 有错误发生
func (server demoServer) OnError(c *gsocket.Connection, err error) {
	fmt.Printf("ERROR: %s - %s\n", c.RemoteAddr(), err.Error())
}

func TestCommitteeServerDemo(t *testing.T) {
	sssa.TestLibraryCombine4()
	return
	port := flag.Int("port", 9001, "listening port")
	id := flag.Int("id", 1, "server ID")
	flag.Parse()
	ServerID = uint16(*id)
	ServerPort = uint16(*port)

	demoServer := &demoServer{}
	//CreateTCPServer 的handler可以传nil
	server := gsocket.CreateTCPServer("127.0.0.1", uint16(*port),
		demoServer.OnConnect, demoServer.OnDisconnect, demoServer.OnRecv, demoServer.OnError)

	err := server.Start()
	if err != nil {
		fmt.Printf("Start Server Error: %s\n", err.Error())
		return
	}
	fmt.Printf("Listening %s...\n", server.Addr())

	time.Sleep(10000000000)
	polynomialPubs, pointers := sssa.GenerateShares(2, 3)
	fmt.Printf("The pointer is %d, %x\n", 1, pointers[0])

	sssa.SendPointer(9001, uint16(*id), 1, pointers[0], polynomialPubs)
	sssa.SendPointer(9002, uint16(*id), 2, pointers[1], polynomialPubs)
	sssa.SendPointer(9003, uint16(*id), 3, pointers[2], polynomialPubs)

	time.Sleep(15000000000)
	sssa.CountSharesPart(uint16(*id))

	time.Sleep(100000000000000)

}

