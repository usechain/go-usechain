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
	"fmt"
	"log"
	"net"
	"sync"
)

// TCPServer 描述一个TCP服务器的结构
type TCPServer struct {
	tcpServerState
	userHandler   tcpEventHandler // 用户的事件处理Handler
	connectionMax int             // 最大连接数，为0则不限制服务器最大连接数
	listener      net.Listener    // 监听句柄
	terminated    bool            // 通知是否停止Service
	wg            sync.WaitGroup  // 等待所有goroutine结束
}

type tcpServerState struct {
	listenAddr      string // 监听地址
	listenPort      uint16 // 监听端口
	connectionCount uint32 // 当前连接数
}

// CreateTCPServer 创建一个TCPServer, 返回*TCPServer
func CreateTCPServer(addr string, port uint16, handlerConnect TCPConnectHandler, handlerDisconnect TCPDisconnectHandler,
	handlerRecv TCPRecvHandler, handlerError TCPErrorHandler) *TCPServer {
	server := &TCPServer{
		tcpServerState: tcpServerState{
			listenAddr:      addr,
			listenPort:      port,
			connectionCount: 0,
		},
		userHandler: tcpEventHandler{
			handlerConnect:    handlerConnect,
			handlerDisconnect: handlerDisconnect,
			handlerRecv:       handlerRecv,
			handlerError:      handlerError,
		},
	}

	return server
}

// Start 开始服务
func (server *TCPServer) Start() error {
	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", server.listenAddr, server.listenPort))
	if err != nil {
		return err
	}

	server.wg.Add(1)

	go func() {
		for {
			if server.terminated {
				server.wg.Done()
				break
			}

			conn, err := listener.Accept()
			if err != nil {
				server.processError(nil, err)
				continue
			}

			go func(conn net.Conn) {
				session := server.makeSession(conn)

				server.processConnect(session)
			}(conn)
		}
	}()

	return nil
}

// Stop 停止服务
func (server *TCPServer) Stop() {
	server.terminated = true
	server.wg.Wait() // 等待结束
}

// ConnectionCount 返回服务器当前连接数
func (server *TCPServer) ConnectionCount() uint32 {
	return server.tcpServerState.connectionCount
}

// SetMaxConnection 设置服务器最大连接数
func (server *TCPServer) SetMaxConnection(maxCount int) {
	server.connectionMax = maxCount
}

// Addr 返回服务器监听的地址
func (server *TCPServer) Addr() string {
	return fmt.Sprintf("%s:%d", server.listenAddr, server.listenPort)
}

func (server *TCPServer) makeSession(conn net.Conn) (session *Connection) {
	session = newConnection(conn)

	server.wg.Add(2)
	go session.recvThread(&server.wg, server.userHandler)
	go session.sendThread(&server.wg)

	return session
}

func (server *TCPServer) processConnect(c *Connection) {
	log.Printf("ACCEPTED: %s\n", c.RemoteAddr())
	if server.userHandler.handlerConnect != nil {
		server.userHandler.handlerConnect(c)
	}
}

func (server *TCPServer) processDisconnect(c *Connection) {
	log.Printf("CONNECTION CLOSED: %s\n", c.RemoteAddr())
	if server.userHandler.handlerDisconnect != nil {
		server.userHandler.handlerDisconnect(c)
	}
}

func (server *TCPServer) processRecv(c *Connection, data []byte) {
	log.Printf("DATA RECVED: %x\n", data)
	if server.userHandler.handlerRecv != nil {
		server.userHandler.handlerRecv(c, data)
	}
}

func (server *TCPServer) processError(c *Connection, err error) {
	log.Printf("ERROR: %s\n", err.Error())
	if server.userHandler.handlerError != nil {
		server.userHandler.handlerError(c, err)
	}
}
