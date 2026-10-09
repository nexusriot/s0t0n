// ja3: compute JA3 (client) and JA3S (server) TLS fingerprints from a pcap.
// The client-side sibling of the jarm tool; reads pcaps like pcap-summary.
// No libpcap/cgo required. Authorized use only.
//
// Usage: ja3 <file.pcap>
package main

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func isGREASE(v uint16) bool {
	return (v&0x0f0f) == 0x0a0a && byte(v>>8) == byte(v&0xff)
}

func join(vals []uint16) string {
	parts := make([]string, 0, len(vals))
	for _, v := range vals {
		if isGREASE(v) {
			continue
		}
		parts = append(parts, strconv.Itoa(int(v)))
	}
	return strings.Join(parts, "-")
}

// parseHello parses a TLS ClientHello(1) or ServerHello(2) from a record payload.
// Returns the JA3/JA3S string, or "" if not a hello.
func parseHello(p []byte) (string, bool) {
	if len(p) < 6 || p[0] != 0x16 {
		return "", false // not a handshake record
	}
	hsType := p[5]
	if hsType != 0x01 && hsType != 0x02 {
		return "", false
	}
	// handshake: type(1) len(3) version(2) random(32) ...
	b := p[5:]
	if len(b) < 38 {
		return "", false
	}
	version := binary.BigEndian.Uint16(b[4:6])
	idx := 6 + 32 // after version + random
	if idx >= len(b) {
		return "", false
	}
	sidLen := int(b[idx])
	idx += 1 + sidLen

	var ciphers []uint16
	isClient := hsType == 0x01
	if isClient {
		if idx+2 > len(b) {
			return "", false
		}
		clen := int(binary.BigEndian.Uint16(b[idx : idx+2]))
		idx += 2
		for i := 0; i+2 <= clen && idx+2 <= len(b); i += 2 {
			ciphers = append(ciphers, binary.BigEndian.Uint16(b[idx:idx+2]))
			idx += 2
		}
		if idx >= len(b) {
			return "", false
		}
		compLen := int(b[idx])
		idx += 1 + compLen
	} else {
		// ServerHello: single chosen cipher then 1 compression byte
		if idx+3 > len(b) {
			return "", false
		}
		ciphers = append(ciphers, binary.BigEndian.Uint16(b[idx:idx+2]))
		idx += 2 + 1
	}

	// Extensions
	var exts, curves, points []uint16
	if idx+2 <= len(b) {
		extTotal := int(binary.BigEndian.Uint16(b[idx : idx+2]))
		idx += 2
		end := idx + extTotal
		for idx+4 <= len(b) && idx < end {
			etype := binary.BigEndian.Uint16(b[idx : idx+2])
			elen := int(binary.BigEndian.Uint16(b[idx+2 : idx+4]))
			val := b[idx+4:]
			if len(val) > elen {
				val = val[:elen]
			}
			exts = append(exts, etype)
			switch etype {
			case 0x000a: // supported_groups (curves)
				if len(val) >= 2 {
					n := int(binary.BigEndian.Uint16(val[:2]))
					for i := 0; i+2 <= n && 2+i+2 <= len(val); i += 2 {
						curves = append(curves, binary.BigEndian.Uint16(val[2+i:4+i]))
					}
				}
			case 0x000b: // ec_point_formats
				if len(val) >= 1 {
					n := int(val[0])
					for i := 0; i < n && 1+i < len(val); i++ {
						points = append(points, uint16(val[1+i]))
					}
				}
			}
			idx += 4 + elen
		}
	}

	var ja3 string
	if isClient {
		ja3 = fmt.Sprintf("%d,%s,%s,%s,%s", version, join(ciphers), join(exts), join(curves), join(points))
	} else {
		ja3 = fmt.Sprintf("%d,%s,%s", version, join(ciphers), join(exts))
	}
	return ja3, true
}

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

	seen := 0
	src := gopacket.NewPacketSource(r, r.LinkType())
	for pkt := range src.Packets() {
		tl := pkt.Layer(layers.LayerTypeTCP)
		if tl == nil {
			continue
		}
		app := pkt.ApplicationLayer()
		if app == nil {
			continue
		}
		ja3str, ok := parseHello(app.Payload())
		if !ok {
			continue
		}
		sum := md5.Sum([]byte(ja3str))
		kind := "JA3 "
		if strings.Count(ja3str, ",") == 2 {
			kind = "JA3S"
		}
		flow := ""
		if n := pkt.NetworkLayer(); n != nil {
			flow = n.NetworkFlow().String()
		}
		fmt.Printf("%s %s  %s\n       %s\n", kind, hex.EncodeToString(sum[:]), flow, ja3str)
		seen++
	}
	fmt.Printf("\n%d TLS hello(s) fingerprinted.\n", seen)
}
