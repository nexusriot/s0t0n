// pcap-summary: read a .pcap file (no libpcap / cgo required) and summarize
// top talkers, L4 protocol mix, DNS queries and plaintext-credential hints.
// A defensive/analysis counterpart to the recon tools. Authorized use only.
//
// Usage: pcap-summary <file.pcap>
package main

import (
	"fmt"
	"os"
	"sort"
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

	talkers := map[string]int{}
	protos := map[string]int{}
	dnsQ := map[string]int{}
	var creds []string
	total, totalBytes := 0, 0

	src := gopacket.NewPacketSource(r, r.LinkType())
	for pkt := range src.Packets() {
		total++
		totalBytes += len(pkt.Data())

		if net := pkt.NetworkLayer(); net != nil {
			f := net.NetworkFlow()
			talkers[f.Src().String()]++
			talkers[f.Dst().String()]++
		}

		switch {
		case pkt.Layer(layers.LayerTypeTCP) != nil:
			protos["tcp"]++
		case pkt.Layer(layers.LayerTypeUDP) != nil:
			protos["udp"]++
		case pkt.Layer(layers.LayerTypeICMPv4) != nil:
			protos["icmp"]++
		case pkt.Layer(layers.LayerTypeARP) != nil:
			protos["arp"]++
		default:
			protos["other"]++
		}

		if dl := pkt.Layer(layers.LayerTypeDNS); dl != nil {
			dns := dl.(*layers.DNS)
			for _, q := range dns.Questions {
				dnsQ[string(q.Name)]++
			}
		}

		if al := pkt.ApplicationLayer(); al != nil {
			scanCreds(al.Payload(), &creds)
		}
	}

	fmt.Printf("Packets: %d   Bytes: %d\n\n", total, totalBytes)

	fmt.Println("== Protocol mix ==")
	for _, kv := range sortMap(protos) {
		fmt.Printf("  %-6s %d\n", kv.k, kv.v)
	}

	fmt.Println("\n== Top talkers ==")
	tt := sortMap(talkers)
	for i, kv := range tt {
		if i >= 10 {
			break
		}
		fmt.Printf("  %-18s %d pkt\n", kv.k, kv.v)
	}

	if len(dnsQ) > 0 {
		fmt.Println("\n== DNS queries ==")
		for i, kv := range sortMap(dnsQ) {
			if i >= 15 {
				break
			}
			fmt.Printf("  %-40s x%d\n", kv.k, kv.v)
		}
	}

	if len(creds) > 0 {
		fmt.Printf("\n== Plaintext credential hints (%d) ==\n", len(creds))
		for _, c := range creds {
			fmt.Printf("  %s\n", c)
		}
	}
}

// scanCreds looks for obvious plaintext secrets in an application payload.
func scanCreds(p []byte, out *[]string) {
	s := string(p)
	for _, line := range strings.Split(s, "\r\n") {
		l := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(l, "Authorization: Basic "):
			*out = append(*out, "HTTP "+l)
		case strings.HasPrefix(strings.ToUpper(l), "USER "),
			strings.HasPrefix(strings.ToUpper(l), "PASS "):
			*out = append(*out, "FTP/POP "+l)
		}
	}
}

type kv struct {
	k string
	v int
}

func sortMap(m map[string]int) []kv {
	out := make([]kv, 0, len(m))
	for k, v := range m {
		out = append(out, kv{k, v})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].v > out[j].v })
	return out
}
