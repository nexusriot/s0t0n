// ssh-audit-lite: read a server's SSH banner and offered algorithms
// (KEXINIT) and flag weak/legacy ones. No auth is attempted. Authorized use only.
//
// Usage: ssh-audit-lite <host> [port]
package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"
)

var weak = map[string]string{
	"diffie-hellman-group1-sha1":   "weak KEX (1024-bit group, SHA-1)",
	"diffie-hellman-group14-sha1":  "legacy KEX (SHA-1)",
	"ssh-rsa":                      "SHA-1 host-key signature",
	"ssh-dss":                      "DSA host key (deprecated)",
	"arcfour":                      "RC4 cipher (broken)",
	"arcfour128":                   "RC4 cipher (broken)",
	"arcfour256":                   "RC4 cipher (broken)",
	"3des-cbc":                     "3DES / CBC (weak)",
	"aes128-cbc":                   "CBC mode (weak)",
	"aes192-cbc":                   "CBC mode (weak)",
	"aes256-cbc":                   "CBC mode (weak)",
	"hmac-md5":                     "MD5 MAC (broken)",
	"hmac-sha1":                    "SHA-1 MAC (legacy)",
	"hmac-sha1-96":                 "SHA-1 MAC (legacy)",
	"none":                         "no encryption/MAC offered",
}

func main() {
	if len(os.Args) < 2 {
		fmt.Printf("Usage: %s <host> [port]\n", os.Args[0])
		os.Exit(1)
	}
	host := os.Args[1]
	port := "22"
	if len(os.Args) > 2 {
		port = os.Args[2]
	}

	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 5*time.Second)
	if err != nil {
		fmt.Fprintf(os.Stderr, "connect: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))

	// Exchange identification strings.
	br := bufio.NewReader(conn)
	banner, err := br.ReadString('\n')
	if err != nil {
		fmt.Fprintf(os.Stderr, "read banner: %v\n", err)
		os.Exit(1)
	}
	banner = strings.TrimRight(banner, "\r\n")
	fmt.Printf("Banner : %s\n", banner)
	if _, err := conn.Write([]byte("SSH-2.0-s0t0n-audit\r\n")); err != nil {
		fmt.Fprintf(os.Stderr, "write ident: %v\n", err)
		os.Exit(1)
	}

	// Read binary packets until we see KEXINIT (msg type 20).
	payload, err := readUntilKexinit(br)
	if err != nil {
		fmt.Fprintf(os.Stderr, "kexinit: %v\n", err)
		os.Exit(1)
	}

	// KEXINIT: byte(20) + 16-byte cookie, then 10 name-lists.
	p := payload[17:]
	labels := []string{"kex", "host-key", "enc c->s", "enc s->c",
		"mac c->s", "mac s->c", "comp c->s", "comp s->c", "lang c->s", "lang s->c"}
	var flagged []string
	for _, label := range labels {
		if len(p) < 4 {
			break
		}
		n := binary.BigEndian.Uint32(p[:4])
		p = p[4:]
		if uint32(len(p)) < n {
			break
		}
		list := string(p[:n])
		p = p[n:]
		fmt.Printf("%-9s: %s\n", label, list)
		for _, alg := range strings.Split(list, ",") {
			// "none" is only a problem for ciphers/MACs, not compression/lang.
			if alg == "none" && !strings.HasPrefix(label, "enc") && !strings.HasPrefix(label, "mac") {
				continue
			}
			if reason, bad := weak[alg]; bad {
				flagged = append(flagged, fmt.Sprintf("  [%s] %s — %s", label, alg, reason))
			}
		}
	}

	fmt.Println()
	if len(flagged) == 0 {
		fmt.Println("No weak algorithms flagged.")
	} else {
		fmt.Printf("%d weak algorithm(s):\n", len(flagged))
		for _, f := range flagged {
			fmt.Println(f)
		}
	}
}

func readUntilKexinit(r *bufio.Reader) ([]byte, error) {
	for attempts := 0; attempts < 5; attempts++ {
		var lenBuf [4]byte
		if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
			return nil, err
		}
		pktLen := binary.BigEndian.Uint32(lenBuf[:])
		if pktLen == 0 || pktLen > 70000 {
			return nil, fmt.Errorf("implausible packet length %d", pktLen)
		}
		pkt := make([]byte, pktLen)
		if _, err := io.ReadFull(r, pkt); err != nil {
			return nil, err
		}
		padLen := int(pkt[0])
		if 1+padLen > len(pkt) {
			return nil, fmt.Errorf("bad padding")
		}
		payload := pkt[1 : len(pkt)-padLen]
		if len(payload) > 0 && payload[0] == 20 { // SSH_MSG_KEXINIT
			return payload, nil
		}
	}
	return nil, fmt.Errorf("KEXINIT not seen")
}
