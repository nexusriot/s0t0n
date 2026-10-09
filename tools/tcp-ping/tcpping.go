// tcp-ping: measure TCP connect latency to host:port over time (no root).
// A userland alternative to icmp-sweep where ICMP is filtered. Authorized use.
//
// Usage: tcp-ping <host> <port> [count] [interval-ms]
package main

import (
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"time"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Printf("Usage: %s <host> <port> [count] [interval-ms]\n", os.Args[0])
		os.Exit(1)
	}
	host, port := os.Args[1], os.Args[2]
	count := 5
	if len(os.Args) > 3 {
		count, _ = strconv.Atoi(os.Args[3])
	}
	interval := 1000 * time.Millisecond
	if len(os.Args) > 4 {
		if ms, err := strconv.Atoi(os.Args[4]); err == nil {
			interval = time.Duration(ms) * time.Millisecond
		}
	}

	addr := net.JoinHostPort(host, port)
	var rtts []time.Duration
	ok := 0
	for i := 0; i < count; i++ {
		start := time.Now()
		conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
		rtt := time.Since(start)
		if err != nil {
			fmt.Printf("seq=%d  FAILED (%v)\n", i, err)
		} else {
			conn.Close()
			ok++
			rtts = append(rtts, rtt)
			fmt.Printf("seq=%d  %s  %v\n", i, addr, rtt.Round(time.Microsecond))
		}
		if i < count-1 {
			time.Sleep(interval)
		}
	}

	fmt.Printf("\n%d/%d succeeded", ok, count)
	if len(rtts) > 0 {
		sort.Slice(rtts, func(i, j int) bool { return rtts[i] < rtts[j] })
		var sum time.Duration
		for _, r := range rtts {
			sum += r
		}
		avg := sum / time.Duration(len(rtts))
		jitter := rtts[len(rtts)-1] - rtts[0]
		fmt.Printf("  min=%v avg=%v max=%v jitter=%v",
			rtts[0].Round(time.Microsecond), avg.Round(time.Microsecond),
			rtts[len(rtts)-1].Round(time.Microsecond), jitter.Round(time.Microsecond))
	}
	fmt.Println()
	if ok == 0 {
		os.Exit(1)
	}
}
