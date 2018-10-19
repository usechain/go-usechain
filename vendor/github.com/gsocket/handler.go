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

// TCPConnectHandler 连接事件
type TCPConnectHandler func(c *Connection)

// TCPDisconnectHandler 断开连接事件
type TCPDisconnectHandler func(c *Connection)

// TCPRecvHandler 收到数据事件
type TCPRecvHandler func(c *Connection, data []byte)

// TCPErrorHandler 有错误发生
type TCPErrorHandler func(c *Connection, err error)

type tcpEventHandler struct {
	handlerConnect    TCPConnectHandler
	handlerDisconnect TCPDisconnectHandler
	handlerRecv       TCPRecvHandler
	handlerError      TCPErrorHandler
}
