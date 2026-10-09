// icmp-sweep: ICMP echo (ping) sweep of a CIDR to find live hosts.
// Complements the ARP scanners by working across subnets/routers.
//
// Requires raw-socket privileges: run with sudo (or grant CAP_NET_RAW).
// Authorized use only — scan networks you own or may test.
package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

const (
	workerCount = 64
	timeout     = 1500 * time.Millisecond
)

func main() {
	if len(os.Args) != 2 {
		fmt.Printf("Usage: sudo %s <CIDR>\n", os.Args[0])
		fmt.Printf("Example: sudo %s 192.168.1.0/24\n", os.Args[0])
		os.Exit(1)
	}

	ip, ipnet, err := net.ParseCIDR(os.Args[1])
	if err != nil {
		log.Fatalf("CIDR parse error: %v", err)
	}

	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		log.Fatalf("listen error (need root/CAP_NET_RAW?): %v", err)
	}
	defer conn.Close()

	// Collect replies concurrently with sending.
	alive := make(map[string]time.Duration)
	var mu sync.Mutex
	done := make(chan struct{})
	sent := make(map[string]time.Time)
	var sentMu sync.Mutex

	go func() {
		buf := make([]byte, 1500)
		for {
			_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			n, peer, err := conn.ReadFrom(buf)
			select {
			case <-done:
				return
			default:
			}
			if err != nil {
				continue
			}
			msg, err := icmp.ParseMessage(ipv4.ICMPTypeEchoReply.Protocol(), buf[:n])
			if err != nil || msg.Type != ipv4.ICMPTypeEchoReply {
				continue
			}
			host := peer.String()
			sentMu.Lock()
			t0, ok := sent[host]
			sentMu.Unlock()
			rtt := time.Duration(0)
			if ok {
				rtt = time.Since(t0)
			}
			mu.Lock()
			if _, seen := alive[host]; !seen {
				alive[host] = rtt
				fmt.Printf("%-15s  up  (%v)\n", host, rtt.Round(time.Millisecond))
			}
			mu.Unlock()
		}
	}()

	// Send echo requests via a bounded worker pool.
	ipCh := make(chan net.IP, 256)
	var wg sync.WaitGroup
	pid := os.Getpid() & 0xffff

	for w := 0; w < workerCount; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for target := range ipCh {
				seq := int(target[len(target)-1])
				wm := icmp.Message{
					Type: ipv4.ICMPTypeEcho, Code: 0,
					Body: &icmp.Echo{ID: pid, Seq: seq, Data: []byte("s0t0n")},
				}
				wb, err := wm.Marshal(nil)
				if err != nil {
					continue
				}
				dst := &net.IPAddr{IP: target}
				sentMu.Lock()
				sent[target.String()] = time.Now()
				sentMu.Unlock()
				if _, err := conn.WriteTo(wb, dst); err != nil {
					continue
				}
			}
		}()
	}

	fmt.Printf("Sweeping %s ...\n", os.Args[1])
	for cur := ip.Mask(ipnet.Mask); ipnet.Contains(cur); incIP(cur) {
		ipCh <- append(net.IP(nil), cur...)
	}
	close(ipCh)
	wg.Wait()

	// Give stragglers time to reply.
	time.Sleep(timeout)
	close(done)

	mu.Lock()
	fmt.Printf("\n%d host(s) up.\n", len(alive))
	mu.Unlock()
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
