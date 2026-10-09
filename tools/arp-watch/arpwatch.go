// arp-watch: passively listen for ARP traffic on an interface and alert on
// newly seen hosts and on IP<->MAC changes (possible ARP spoofing). The
// defensive counterpart to go-arpscan. Needs root. Authorized use only.
//
// Usage: sudo arp-watch <interface>
package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/mdlayher/packet"
)

const etherTypeARP = 0x0806

func main() {
	if len(os.Args) != 2 {
		fmt.Printf("Usage: sudo %s <interface>\n", os.Args[0])
		os.Exit(1)
	}
	iface, err := net.InterfaceByName(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "interface: %v\n", err)
		os.Exit(1)
	}

	conn, err := packet.Listen(iface, packet.Raw, etherTypeARP, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "listen (need root/CAP_NET_RAW?): %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	fmt.Printf("Watching ARP on %s (Ctrl-C to stop)...\n", os.Args[1])
	table := map[string]string{} // ip -> mac
	buf := make([]byte, 1500)

	for {
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			continue
		}
		if n < 14+28 {
			continue
		}
		frame := buf[:n]
		if binary.BigEndian.Uint16(frame[12:14]) != etherTypeARP {
			continue
		}
		arp := frame[14:]
		// ARP: htype(2) ptype(2) hlen(1) plen(1) oper(2) sha(6) spa(4) tha(6) tpa(4)
		if len(arp) < 28 {
			continue
		}
		oper := binary.BigEndian.Uint16(arp[6:8])
		senderMAC := net.HardwareAddr(arp[8:14]).String()
		senderIP := net.IP(arp[14:18]).String()

		ts := time.Now().Format("15:04:05")
		opName := "reply"
		if oper == 1 {
			opName = "request"
		}

		prev, seen := table[senderIP]
		switch {
		case !seen:
			table[senderIP] = senderMAC
			fmt.Printf("[%s] NEW   %-15s is-at %s (%s)\n", ts, senderIP, senderMAC, opName)
		case prev != senderMAC:
			fmt.Printf("[%s] CHANGE %-15s %s -> %s  (possible spoof)\n", ts, senderIP, prev, senderMAC)
			table[senderIP] = senderMAC
		}
	}
}
