// net-neighbors: unified host discovery. For targets on the interface's own
// subnet it uses ARP (fast, reliable on a LAN); for off-link targets it falls
// back to ICMP echo. Prints one table with the method used. Needs root.
// Authorized use only.
//
// Usage: sudo net-neighbors <interface> <CIDR>
package main

import (
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/mdlayher/arp"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

const arpWorkers = 20

type found struct{ ip, info, method string }

func main() {
	if len(os.Args) != 3 {
		fmt.Printf("Usage: sudo %s <interface> <CIDR>\n", os.Args[0])
		os.Exit(1)
	}
	ifaceName, cidr := os.Args[1], os.Args[2]

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("interface error: %v", err)
	}
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		log.Fatalf("CIDR parse error: %v", err)
	}

	// Collect the interface's on-link IPv4 subnets.
	var onlink []*net.IPNet
	addrs, _ := iface.Addrs()
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil {
			onlink = append(onlink, n)
		}
	}
	isOnlink := func(ip net.IP) bool {
		for _, n := range onlink {
			if n.Contains(ip) {
				return true
			}
		}
		return false
	}

	// Partition the target range.
	var arpTargets, icmpTargets []net.IP
	start := ipnet.IP.Mask(ipnet.Mask)
	for ip := cloneIP(start); ipnet.Contains(ip); incIP(ip) {
		if isSelf(ip, onlink) {
			continue
		}
		if isOnlink(ip) {
			arpTargets = append(arpTargets, cloneIP(ip))
		} else {
			icmpTargets = append(icmpTargets, cloneIP(ip))
		}
	}

	results := make(chan found, 256)
	var wg sync.WaitGroup

	// ARP phase (worker pool, each its own socket).
	if len(arpTargets) > 0 {
		jobs := make(chan net.IP, 256)
		for w := 0; w < arpWorkers; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				c, err := arp.Dial(iface)
				if err != nil {
					return
				}
				defer c.Close()
				for ip := range jobs {
					addr, err := netip.ParseAddr(ip.String())
					if err != nil {
						continue
					}
					_ = c.SetReadDeadline(time.Now().Add(1 * time.Second))
					if mac, err := c.Resolve(addr); err == nil {
						results <- found{ip.String(), mac.String(), "arp"}
					}
					time.Sleep(10 * time.Millisecond)
				}
			}()
		}
		for _, ip := range arpTargets {
			jobs <- ip
		}
		close(jobs)
	}

	// ICMP phase.
	if len(icmpTargets) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			icmpScan(icmpTargets, results)
		}()
	}

	go func() { wg.Wait(); close(results) }()

	fmt.Printf("Scanning %s (%d on-link / %d routed) ...\n\n", cidr, len(arpTargets), len(icmpTargets))
	count := 0
	for r := range results {
		count++
		fmt.Printf("%-15s  %-5s  %s\n", r.ip, r.method, r.info)
	}
	fmt.Printf("\n%d host(s) up.\n", count)
}

func icmpScan(targets []net.IP, out chan<- found) {
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		log.Printf("icmp listen (need root?): %v", err)
		return
	}
	defer conn.Close()
	pid := os.Getpid() & 0xffff

	seen := map[string]bool{}
	var mu sync.Mutex
	done := make(chan struct{})
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
			mu.Lock()
			if !seen[host] {
				seen[host] = true
				out <- found{host, "echo reply", "icmp"}
			}
			mu.Unlock()
		}
	}()

	for _, ip := range targets {
		wm := icmp.Message{Type: ipv4.ICMPTypeEcho, Body: &icmp.Echo{
			ID: pid, Seq: int(ip[len(ip)-1]), Data: []byte("s0t0n")}}
		wb, err := wm.Marshal(nil)
		if err != nil {
			continue
		}
		_, _ = conn.WriteTo(wb, &net.IPAddr{IP: ip})
	}
	time.Sleep(1500 * time.Millisecond)
	close(done)
}

func isSelf(ip net.IP, onlink []*net.IPNet) bool {
	for _, n := range onlink {
		if n.IP.Equal(ip) {
			return true
		}
	}
	return false
}
func cloneIP(ip net.IP) net.IP { return append(net.IP(nil), ip...) }
func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
