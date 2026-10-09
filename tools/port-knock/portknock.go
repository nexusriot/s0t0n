// port-knock: send a knock sequence to a host, then probe a target port.
// Useful for testing your own knockd / fwknop setups. Authorized use only.
//
// Usage:
//   port-knock <host> <knock-ports csv> <target-port> [tcp|udp] [delay-ms]
//   port-knock 10.0.0.1 7000,8000,9000 22 tcp 300
package main

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

func main() {
	if len(os.Args) < 4 {
		fmt.Printf("Usage: %s <host> <knock-ports csv> <target-port> [tcp|udp] [delay-ms]\n", os.Args[0])
		os.Exit(1)
	}
	host := os.Args[1]
	knocks := strings.Split(os.Args[2], ",")
	target := os.Args[3]
	proto := "tcp"
	if len(os.Args) > 4 {
		proto = os.Args[4]
	}
	delay := 300 * time.Millisecond
	if len(os.Args) > 5 {
		if ms, err := strconv.Atoi(os.Args[5]); err == nil {
			delay = time.Duration(ms) * time.Millisecond
		}
	}

	fmt.Printf("Knocking %s via %s: %s\n", host, proto, strings.Join(knocks, ", "))
	for _, p := range knocks {
		p = strings.TrimSpace(p)
		addr := net.JoinHostPort(host, p)
		// A knock is just an attempt; refusal/timeout is expected and fine.
		conn, err := net.DialTimeout(proto, addr, 500*time.Millisecond)
		if err == nil {
			conn.Close()
		}
		fmt.Printf("  knock %s/%s\n", p, proto)
		time.Sleep(delay)
	}

	fmt.Printf("Probing target %s/tcp ...\n", target)
	addr := net.JoinHostPort(host, target)
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		fmt.Printf("  port %s: CLOSED/filtered (%v)\n", target, err)
		os.Exit(1)
	}
	conn.Close()
	fmt.Printf("  port %s: OPEN — knock sequence worked\n", target)
}
