// whois-asn: map IPv4 addresses to ASN / prefix / org using Team Cymru's
// DNS interface (origin.asn.cymru.com). Annotate scan results with the owning
// network. Pure stdlib. Authorized use only.
//
// Usage: whois-asn 8.8.8.8 1.1.1.1 ...   (or pipe one IP per line on stdin)
package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
)

func reverseV4(ip net.IP) string {
	ip = ip.To4()
	if ip == nil {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d.%d", ip[3], ip[2], ip[1], ip[0])
}

// lookupASN returns asn, prefix, cc for an IPv4 address via Team Cymru DNS.
func lookupASN(ipStr string) (string, string, string, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil || ip.To4() == nil {
		return "", "", "", fmt.Errorf("not an IPv4 address")
	}
	q := reverseV4(ip) + ".origin.asn.cymru.com"
	txts, err := net.LookupTXT(q)
	if err != nil || len(txts) == 0 {
		return "", "", "", fmt.Errorf("no ASN record")
	}
	// "15169 | 8.8.8.0/24 | US | arin | ..."
	parts := strings.Split(txts[0], "|")
	asn := strings.TrimSpace(parts[0])
	prefix, cc := "", ""
	if len(parts) > 1 {
		prefix = strings.TrimSpace(parts[1])
	}
	if len(parts) > 2 {
		cc = strings.TrimSpace(parts[2])
	}
	// First ASN only if a set is returned.
	asn = strings.Fields(asn)[0]
	return asn, prefix, cc, nil
}

func asnOrg(asn string) string {
	txts, err := net.LookupTXT("AS" + asn + ".asn.cymru.com")
	if err != nil || len(txts) == 0 {
		return ""
	}
	parts := strings.Split(txts[0], "|")
	if len(parts) > 4 {
		return strings.TrimSpace(parts[4])
	}
	return ""
}

func process(ip string) {
	asn, prefix, cc, err := lookupASN(ip)
	if err != nil {
		fmt.Printf("%-15s  %v\n", ip, err)
		return
	}
	org := asnOrg(asn)
	fmt.Printf("%-15s  AS%-7s %-18s %-3s %s\n", ip, asn, prefix, cc, org)
}

func main() {
	ips := os.Args[1:]
	if len(ips) == 0 {
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line != "" && !strings.HasPrefix(line, "#") {
				ips = append(ips, line)
			}
		}
	}
	if len(ips) == 0 {
		fmt.Printf("Usage: %s <ip> [ip ...]   (or pipe IPs on stdin)\n", os.Args[0])
		os.Exit(1)
	}
	fmt.Printf("%-15s  %-9s %-18s %-3s %s\n", "IP", "ASN", "PREFIX", "CC", "ORG")
	for _, ip := range ips {
		process(ip)
	}
}
