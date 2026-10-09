// dns-sniff: passive DNS logger from a pcap — who queried what, and the
// answers returned. Defensive counterpart to dns-recon. Pure Go (no libpcap).
// Authorized use only.
//
// Usage: dns-sniff <file.pcap>
package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Printf("Usage: %s <file.pcap>\n", os.Args[0])
		os.Exit(1)
	}
	f, err := os.Open(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "open: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()
	r, err := pcapgo.NewReader(f)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pcap: %v\n", err)
		os.Exit(1)
	}

	queries := map[string]int{}
	count := 0
	src := gopacket.NewPacketSource(r, r.LinkType())
	for pkt := range src.Packets() {
		dl := pkt.Layer(layers.LayerTypeDNS)
		if dl == nil {
			continue
		}
		dns := dl.(*layers.DNS)
		var client string
		if n := pkt.NetworkLayer(); n != nil {
			client = n.NetworkFlow().Src().String()
		}
		ts := pkt.Metadata().Timestamp.Format("15:04:05")

		if !dns.QR { // query
			for _, q := range dns.Questions {
				name := string(q.Name)
				queries[name]++
				count++
				fmt.Printf("[%s] %-15s Q  %s %s\n", ts, client, q.Type, name)
			}
		} else { // response
			for _, a := range dns.Answers {
				val := answerString(a)
				if val != "" {
					fmt.Printf("[%s] %-15s A  %s %s -> %s\n", ts, client, a.Type, string(a.Name), val)
				}
			}
		}
	}

	fmt.Printf("\n%d quer(ies) across %d distinct name(s).\n", count, len(queries))
}

func answerString(a layers.DNSResourceRecord) string {
	switch a.Type {
	case layers.DNSTypeA, layers.DNSTypeAAAA:
		if a.IP != nil {
			return a.IP.String()
		}
	case layers.DNSTypeCNAME:
		return string(a.CNAME)
	case layers.DNSTypeNS:
		return string(a.NS)
	case layers.DNSTypePTR:
		return string(a.PTR)
	case layers.DNSTypeTXT:
		return strings.Join(bytesToStrings(a.TXTs), " ")
	}
	return ""
}

func bytesToStrings(b [][]byte) []string {
	out := make([]string, len(b))
	for i := range b {
		out[i] = string(b[i])
	}
	return out
}
