// smb-enum: send an SMB2 NEGOTIATE request and report the dialect chosen and
// whether message signing is required. Light recon that pairs with
// net-neighbors. Authorized use only.
//
// Usage: smb-enum <host> [port]   (default port 445)
package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"time"
)

// Minimal SMB2 NEGOTIATE request offering dialects 0x0202..0x0311.
func negotiateRequest() []byte {
	// SMB2 header (64 bytes)
	h := make([]byte, 64)
	copy(h[0:4], []byte{0xFE, 'S', 'M', 'B'}) // ProtocolId
	binary.LittleEndian.PutUint16(h[4:6], 64) // StructureSize
	// Command = 0 (NEGOTIATE), MessageId = 0
	// Negotiate request body
	dialects := []uint16{0x0202, 0x0210, 0x0300, 0x0302, 0x0311}
	body := make([]byte, 36+len(dialects)*2)
	binary.LittleEndian.PutUint16(body[0:2], 36)                     // StructureSize
	binary.LittleEndian.PutUint16(body[2:4], uint16(len(dialects)))  // DialectCount
	binary.LittleEndian.PutUint16(body[4:6], 0x0001)                 // SecurityMode: signing enabled
	// Capabilities, ClientGuid (16 bytes) left zero
	for i, d := range dialects {
		binary.LittleEndian.PutUint16(body[36+i*2:], d)
	}
	smb := append(h, body...)

	// NetBIOS session service header: 0x00 + 3-byte length
	nb := make([]byte, 4)
	nb[0] = 0x00
	nb[1] = byte(len(smb) >> 16)
	nb[2] = byte(len(smb) >> 8)
	nb[3] = byte(len(smb))
	return append(nb, smb...)
}

func dialectName(d uint16) string {
	switch d {
	case 0x0202:
		return "SMB 2.0.2"
	case 0x0210:
		return "SMB 2.1"
	case 0x0300:
		return "SMB 3.0"
	case 0x0302:
		return "SMB 3.0.2"
	case 0x0311:
		return "SMB 3.1.1"
	case 0x02FF:
		return "SMB2 wildcard (2.???)"
	default:
		return fmt.Sprintf("unknown(0x%04x)", d)
	}
}

func main() {
	if len(os.Args) < 2 {
		fmt.Printf("Usage: %s <host> [port]\n", os.Args[0])
		os.Exit(1)
	}
	host := os.Args[1]
	port := "445"
	if len(os.Args) > 2 {
		port = os.Args[2]
	}

	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 5*time.Second)
	if err != nil {
		fmt.Fprintf(os.Stderr, "connect: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := conn.Write(negotiateRequest()); err != nil {
		fmt.Fprintf(os.Stderr, "write: %v\n", err)
		os.Exit(1)
	}

	// Read NetBIOS length then the SMB2 response.
	nbHdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, nbHdr); err != nil {
		fmt.Fprintf(os.Stderr, "no SMB response: %v\n", err)
		os.Exit(1)
	}
	length := int(nbHdr[1])<<16 | int(nbHdr[2])<<8 | int(nbHdr[3])
	resp := make([]byte, length)
	if _, err := io.ReadFull(conn, resp); err != nil {
		fmt.Fprintf(os.Stderr, "short read: %v\n", err)
		os.Exit(1)
	}
	if len(resp) < 72 || resp[0] != 0xFE {
		fmt.Fprintf(os.Stderr, "not an SMB2 response\n")
		os.Exit(1)
	}

	// Negotiate response body starts at offset 64.
	body := resp[64:]
	securityMode := binary.LittleEndian.Uint16(body[2:4])
	dialect := binary.LittleEndian.Uint16(body[4:6])

	fmt.Printf("%s:%s\n", host, port)
	fmt.Printf("  Dialect        : %s\n", dialectName(dialect))
	fmt.Printf("  Signing enabled: %v\n", securityMode&0x0001 != 0)
	fmt.Printf("  Signing required: %v\n", securityMode&0x0002 != 0)
}
