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
	"bufio"
	"log"
	"os"
)

type demoServer struct{}

// OnConnect 客户端连接事件
func (server demoServer) OnConnect(c *Connection) {
	log.Printf("CONNECTED: %s\n", c.RemoteAddr())
}

// OnDisconnect 客户端断开连接事件
func (server demoServer) OnDisconnect(c *Connection) {
	log.Printf("DISCONNECTED: %s\n", c.RemoteAddr())
}

// OnRecv 收到客户端发来的数据
func (server demoServer) OnRecv(c *Connection, data []byte) {
	log.Printf("DATA RECVED: %s %d - %v\n", c.RemoteAddr(), len(data), data)
	c.Send(data)
}

// OnError 有错误发生
func (server demoServer) OnError(c *Connection, err error) {
	log.Printf("ERROR: %s - %s\n", c.RemoteAddr(), err.Error())
}

func main() {
	demoServer := &demoServer{}
	//CreateTCPServer 的handler可以传nil
	server := CreateTCPServer("0.0.0.0", 9595,
		demoServer.OnConnect, demoServer.OnDisconnect, demoServer.OnRecv, demoServer.OnError)

	err := server.Start()
	if err != nil {
		log.Printf("Start Server Error: %s\n", err.Error())
		return
	}

	log.Printf("Listening %s...\n", server.Addr())

	pause()
}

func pause() {
	println("按回车键退出...\n")
	r := bufio.NewReader(os.Stdin)
	r.ReadByte()
}
