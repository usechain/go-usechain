# gsocket
一个轻量级的golang socket通信库, 与协议无关，简洁的好用API接口，把Session管理和协议处理交给调用者，以求最大的灵活性

# 安装
go get github.com/xikug/gsocket

# 使用

## Server
```go

package main

import (
	"bufio"
	"log"
	"os"

	"github.com/xikug/gsocket"
)

type demoServer struct{}

// OnConnect 客户端连接事件
func (server demoServer) OnConnect(c *gsocket.Connection) {
	log.Printf("CONNECTED: %s\n", c.RemoteAddr())
}

// OnDisconnect 客户端断开连接事件
func (server demoServer) OnDisconnect(c *gsocket.Connection) {
	log.Printf("DISCONNECTED: %s\n", c.RemoteAddr())
}

// OnRecv 收到客户端发来的数据
func (server demoServer) OnRecv(c *gsocket.Connection, data []byte) {
	log.Printf("DATA RECVED: %s %d - %v\n", c.RemoteAddr(), len(data), data)
	c.Send(data)
}

// OnError 有错误发生
func (server demoServer) OnError(c *gsocket.Connection, err error) {
	log.Printf("ERROR: %s - %s\n", c.RemoteAddr(), err.Error())
}

func main() {
	demoServer := &demoServer{}
	//CreateTCPServer 的handler可以传nil
	server := gsocket.CreateTCPServer("0.0.0.0", 9595,
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

```

## Client
```go
package main

import (
	"bufio"
	"log"
	"os"

	"github.com/xikug/gsocket"
)

type demoClient struct{}

func (client *demoClient) OnConnect(c *gsocket.Connection) {
	log.Printf("CONNECTED: %s\n", c.RemoteAddr())
}

func (client *demoClient) OnDisconnect(c *gsocket.Connection) {
	log.Printf("DISCONNECTED: %s\n", c.RemoteAddr())
}

func (client *demoClient) OnRecv(c *gsocket.Connection, data []byte) {
	log.Printf("DATA RECVED: %s %d - %v\n", c.RemoteAddr(), len(data), data)
}

func (client *demoClient) OnError(c *gsocket.Connection, err error) {
	log.Printf("ERROR: %s - %s\n", c.RemoteAddr(), err.Error())
}

func main() {
	demoClient := &demoClient{}

	client := gsocket.CreateTCPClient(demoClient.OnConnect, demoClient.OnDisconnect, demoClient.OnRecv, demoClient.OnError)

	err := client.Connect("127.0.0.1", 9595)
	if err != nil {
		log.Printf("Coneect Server Error: %s\n", err.Error())
		return
	}

	log.Printf("Connect Server %s Success\n", client.RemoteAddr())

	client.Send([]byte("Hello World!!!"))

	pause()
	client.Close()
}

func pause() {
	println("按回车键退出...\n")
	r := bufio.NewReader(os.Stdin)
	r.ReadByte()
}
```
