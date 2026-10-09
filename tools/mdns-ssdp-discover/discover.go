// mdns-ssdp-discover: passive-ish LAN service discovery via SSDP (UPnP) and
// mDNS/DNS-SD. Sends a multicast query on each protocol and prints responders.
// No special privileges required. Authorized use only.
package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const waitFor = 3 * time.Second

func main() {
	fmt.Println("== SSDP (UPnP) ==")
	if err := ssdpDiscover(); err != nil {
		fmt.Fprintf(os.Stderr, "ssdp: %v\n", err)
	}
	fmt.Println("\n== mDNS / DNS-SD ==")
	if err := mdnsDiscover(); err != nil {
		fmt.Fprintf(os.Stderr, "mdns: %v\n", err)
	}
}

func ssdpDiscover() error {
	addr, _ := net.ResolveUDPAddr("udp4", "239.255.255.250:1900")
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return err
	}
	defer conn.Close()

	msearch := strings.Join([]string{
		"M-SEARCH * HTTP/1.1",
		"HOST: 239.255.255.250:1900",
		`MAN: "ssdp:discover"`,
		"MX: 2",
		"ST: ssdp:all",
		"", "",
	}, "\r\n")

	if _, err := conn.WriteToUDP([]byte(msearch), addr); err != nil {
		return err
	}

	_ = conn.SetReadDeadline(time.Now().Add(waitFor))
	seen := map[string]bool{}
	buf := make([]byte, 2048)
	for {
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			break
		}
		resp := string(buf[:n])
		st := headerValue(resp, "ST")
		server := headerValue(resp, "SERVER")
		location := headerValue(resp, "LOCATION")
		key := src.IP.String() + st
		if seen[key] {
			continue
		}
		seen[key] = true
		fmt.Printf("%-15s  ST=%s\n", src.IP, st)
		if server != "" {
			fmt.Printf("                 SERVER=%s\n", server)
		}
		if location != "" {
			fmt.Printf("                 LOCATION=%s\n", location)
		}
	}
	fmt.Printf("%d SSDP responder(s).\n", len(seen))
	return nil
}

func headerValue(resp, key string) string {
	sc := bufio.NewScanner(strings.NewReader(resp))
	for sc.Scan() {
		line := sc.Text()
		if idx := strings.Index(line, ":"); idx != -1 {
			if strings.EqualFold(strings.TrimSpace(line[:idx]), key) {
				return strings.TrimSpace(line[idx+1:])
			}
		}
	}
	return ""
}

func mdnsDiscover() error {
	addr, _ := net.ResolveUDPAddr("udp4", "224.0.0.251:5353")
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return err
	}
	defer conn.Close()

	m := new(dns.Msg)
	m.SetQuestion("_services._dns-sd._udp.local.", dns.TypePTR)
	m.RecursionDesired = false
	wire, err := m.Pack()
	if err != nil {
		return err
	}
	if _, err := conn.WriteToUDP(wire, addr); err != nil {
		return err
	}

	_ = conn.SetReadDeadline(time.Now().Add(waitFor))
	services := map[string]bool{}
	buf := make([]byte, 65535)
	for {
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			break
		}
		resp := new(dns.Msg)
		if err := resp.Unpack(buf[:n]); err != nil {
			continue
		}
		for _, rr := range append(resp.Answer, resp.Extra...) {
			switch v := rr.(type) {
			case *dns.PTR:
				if !services[v.Ptr] {
					services[v.Ptr] = true
					fmt.Printf("%-15s  PTR  %s\n", src.IP, v.Ptr)
				}
			case *dns.SRV:
				fmt.Printf("%-15s  SRV  %s:%d\n", src.IP, v.Target, v.Port)
			case *dns.A:
				fmt.Printf("%-15s  A    %s -> %s\n", src.IP, v.Hdr.Name, v.A)
			}
		}
	}
	fmt.Printf("%d distinct mDNS service name(s).\n", len(services))
	return nil
}
