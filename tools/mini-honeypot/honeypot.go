// mini-honeypot: open several TCP ports and log the source address and first
// bytes of anyone who connects. Catches scanners on your own network; the
// active counterpart to arp-watch. Authorized use only (run on your own host).
//
// Usage: mini-honeypot <port[,port,...]>   e.g. mini-honeypot 23,2323,8080
package main

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

func handle(conn net.Conn, port string) {
	defer conn.Close()
	src := conn.RemoteAddr().String()
	ts := time.Now().Format("2006-01-02 15:04:05")
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 512)
	n, _ := conn.Read(buf)
	data := strings.TrimRight(fmt.Sprintf("%q", string(buf[:n])), "\x00")
	fmt.Printf("[%s] port=%s from=%s bytes=%d data=%s\n", ts, port, src, n, data)
}

func listen(port string) {
	ln, err := net.Listen("tcp", ":"+port)
	if err != nil {
		fmt.Fprintf(os.Stderr, "port %s: %v\n", port, err)
		return
	}
	fmt.Printf("listening on :%s\n", port)
	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go handle(conn, port)
	}
}

func main() {
	if len(os.Args) != 2 {
		fmt.Printf("Usage: %s <port[,port,...]>\n", os.Args[0])
		os.Exit(1)
	}
	ports := strings.Split(os.Args[1], ",")
	for _, p := range ports[1:] {
		go listen(strings.TrimSpace(p))
	}
	listen(strings.TrimSpace(ports[0])) // block on the first
}
