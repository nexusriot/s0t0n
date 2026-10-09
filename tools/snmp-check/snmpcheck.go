// snmp-check: try a list of SNMP community strings (v1/v2c) against a host and,
// on success, read sysDescr.0. High-signal recon for misconfigured devices.
// Authorized use only.
//
// Usage: snmp-check <host> [community[,community,...]]
//   default communities: public,private
package main

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

// sysDescr.0 = 1.3.6.1.2.1.1.1.0  -> BER OID bytes
var sysDescrOID = []byte{0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00}

// tlv builds a BER type-length-value (short/long form length).
func tlv(tag byte, body []byte) []byte {
	out := []byte{tag}
	l := len(body)
	if l < 128 {
		out = append(out, byte(l))
	} else if l < 256 {
		out = append(out, 0x81, byte(l))
	} else {
		out = append(out, 0x82, byte(l>>8), byte(l))
	}
	return append(out, body...)
}

// buildGet assembles an SNMP GetRequest for sysDescr.0.
func buildGet(version byte, community string) []byte {
	// VarBind: SEQUENCE { OID, NULL }
	varbind := tlv(0x30, append(tlv(0x06, sysDescrOID), tlv(0x05, nil)...))
	varbindList := tlv(0x30, varbind)
	// PDU GetRequest (0xA0): request-id, error-status, error-index, varbinds
	reqID := tlv(0x02, []byte{0x00, 0x00, 0x00, 0x01})
	errStat := tlv(0x02, []byte{0x00})
	errIdx := tlv(0x02, []byte{0x00})
	pduBody := append(append(append(reqID, errStat...), errIdx...), varbindList...)
	pdu := tlv(0xA0, pduBody)
	// Message: SEQUENCE { version, community, PDU }
	ver := tlv(0x02, []byte{version})
	comm := tlv(0x04, []byte(community))
	return tlv(0x30, append(append(ver, comm...), pdu...))
}

// extractOctetString finds the sysDescr OCTET STRING value in the response.
func extractOctetString(data []byte) string {
	// Walk to the last OCTET STRING (0x04) after the OID in the varbind.
	for i := 0; i+2 < len(data); i++ {
		if data[i] == 0x04 {
			l := int(data[i+1])
			if l < 128 && i+2+l <= len(data) && l > 1 {
				s := string(data[i+2 : i+2+l])
				if isPrintable(s) && len(s) > 3 {
					return s
				}
			}
		}
	}
	return ""
}

func isPrintable(s string) bool {
	for _, c := range s {
		if c < 32 && c != '\n' && c != '\r' && c != '\t' {
			return false
		}
	}
	return true
}

func try(host, community string, version byte) (string, bool) {
	conn, err := net.DialTimeout("udp", net.JoinHostPort(host, "161"), 2*time.Second)
	if err != nil {
		return "", false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write(buildGet(version, community)); err != nil {
		return "", false
	}
	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return "", false
	}
	descr := extractOctetString(buf[:n])
	return descr, true
}

func main() {
	if len(os.Args) < 2 {
		fmt.Printf("Usage: %s <host> [community[,community,...]]\n", os.Args[0])
		os.Exit(1)
	}
	host := os.Args[1]
	communities := []string{"public", "private"}
	if len(os.Args) > 2 {
		communities = strings.Split(os.Args[2], ",")
	}

	found := 0
	for _, c := range communities {
		c = strings.TrimSpace(c)
		for _, v := range []struct {
			b    byte
			name string
		}{{0x00, "v1"}, {0x01, "v2c"}} {
			if descr, ok := try(host, c, v.b); ok {
				found++
				if descr != "" {
					fmt.Printf("[+] %s/%s community %q OK — sysDescr: %s\n", host, v.name, c, descr)
				} else {
					fmt.Printf("[+] %s/%s community %q responded\n", host, v.name, c)
				}
			}
		}
	}
	if found == 0 {
		fmt.Printf("No SNMP response from %s (filtered, down, or no matching community).\n", host)
		os.Exit(1)
	}
}
