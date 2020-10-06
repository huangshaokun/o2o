package main

import (
	"flag"
	"io"
	"log"
	"net"
	"runtime"
)

var (
	serverPort = flag.String("p", ":8080", "监听端口")
	proxyAddr  = flag.String("f", "ip.lyl.hk:80", "代理地址")
)

func main() {
	flag.Parse()
	runtime.GOMAXPROCS(runtime.NumCPU())
	log.SetFlags(log.Flags() | log.Lshortfile)

	log.Println("Server:", *serverPort)
	log.Println("Forward:", *proxyAddr)
	l, err := net.Listen("tcp", *serverPort)
	if err != nil {
		log.Fatal(err)
	}

	for {
		conn, err := l.Accept()
		if err != nil {
			log.Fatal(err)
		}

		go proxy(conn)
	}
}

func proxy(conn net.Conn) {
	defer conn.Close()

	local, err := net.Dial("tcp", *proxyAddr)
	if err != nil {
		return
	}

	ch := make(chan int, 1)
	go func() {
		io.Copy(local, conn)
		select {
		case ch <- 1:
		default:
		}
	}()
	go func() {
		io.Copy(conn, local)
		select {
		case ch <- 1:
		default:
		}
	}()
	<-ch
	local.Close()
}
