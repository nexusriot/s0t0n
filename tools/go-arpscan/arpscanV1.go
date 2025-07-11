package main

import (
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"time"

	"github.com/mdlayher/arp"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Printf("Usage: sudo %s <interface> <CIDR>\n", os.Args[0])
		os.Exit(1)
	}

	ifaceName := os.Args[1]
	cidr := os.Args[2]

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("interface error: %v", err)
	}

	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		log.Fatalf("CIDR parse error: %v", err)
	}

	c, err := arp.Dial(iface)
	if err != nil {
		log.Fatalf("ARP dial error: %v", err)
	}
	defer c.Close()

	fmt.Println("Scanning...")

	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); incIP(ip) {
		// Skip own IP
		if isOwnIP(ip, iface) {
			continue
		}

		addr, err := netip.ParseAddr(ip.String())
		if err != nil {
			continue
		}

		_ = c.SetReadDeadline(time.Now().Add(1 * time.Second))
		mac, err := c.Resolve(addr)
		if err == nil {
			fmt.Printf("IP: %-15s MAC: %s\n", ip, mac)
		}
		time.Sleep(30 * time.Millisecond) // rate limit
	}
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

