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
)

const workerCount = 20

func main() {
	if len(os.Args) != 3 {
		fmt.Printf("Usage: sudo %s <interface> <CIDR>\n", os.Args[0])
		os.Exit(1)
	}

	ifaceName := os.Args[1]
	cidr := os.Args[2]

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("Interface error: %v", err)
	}

	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		log.Fatalf("CIDR parse error: %v", err)
	}

	ipCh := make(chan net.IP, 256)
	var wg sync.WaitGroup
	var mu sync.Mutex

	fmt.Println("Scanning...")

	// Start N workers, each with its own ARP socket
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			c, err := arp.Dial(iface)
			if err != nil {
				log.Printf("Worker %d: ARP dial error: %v\n", workerID, err)
				return
			}
			defer c.Close()

			for ip := range ipCh {
				addr, err := netip.ParseAddr(ip.String())
				if err != nil {
					continue
				}
				_ = c.SetReadDeadline(time.Now().Add(1 * time.Second))
				mac, err := c.Resolve(addr)
				if err == nil {
					mu.Lock()
					fmt.Printf("IP: %-15s  MAC: %s\n", ip, mac)
					mu.Unlock()
				}
				time.Sleep(10 * time.Millisecond) // pacing
			}
		}(i)
	}

	// Feed IPs
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); incIP(ip) {
		if isOwnIP(ip, iface) {
			continue
		}
		ipCh <- append(net.IP(nil), ip...)
	}
	close(ipCh)

	wg.Wait()
}

func isOwnIP(ip net.IP, iface *net.Interface) bool {
	addrs, _ := iface.Addrs()
	for _, a := range addrs {
		if ip.String() == a.(*net.IPNet).IP.String() {
			return true
		}
	}
	return false
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

