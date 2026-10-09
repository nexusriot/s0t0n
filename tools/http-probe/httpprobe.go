// http-probe: fetch a list of URLs and record status, final URL, title,
// Server + security headers, redirect chain and a shodan-style favicon mmh3
// hash. A clearnet sibling of onion-batch. Authorized use only.
//
// Usage: http-probe <urls.txt>   (one URL per line; '#' comments ignored)
package main

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/spaolacci/murmur3"
)

var titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

const maxBody = 512 * 1024

func mkClient() *http.Client {
	tr := &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives: true,
	}
	return &http.Client{
		Timeout:   15 * time.Second,
		Transport: tr,
		// Record the redirect chain; stop after 10 hops.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

func title(body []byte) string {
	m := titleRe.FindSubmatch(body)
	if m == nil {
		return "-"
	}
	t := strings.Join(strings.Fields(string(m[1])), " ")
	if len(t) > 70 {
		t = t[:70]
	}
	return t
}

// faviconHash fetches /favicon.ico and returns the shodan-style mmh3 hash
// (murmur3 of the base64-with-newlines body), or "" if unavailable.
func faviconHash(client *http.Client, base string) string {
	u := strings.TrimRight(base, "/") + "/favicon.ico"
	resp, err := client.Get(u)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return ""
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil || len(raw) == 0 {
		return ""
	}
	b64 := base64.StdEncoding.EncodeToString(raw)
	// Shodan inserts a newline every 76 chars and a trailing newline.
	var sb strings.Builder
	for i := 0; i < len(b64); i += 76 {
		end := i + 76
		if end > len(b64) {
			end = len(b64)
		}
		sb.WriteString(b64[i:end])
		sb.WriteByte('\n')
	}
	h := int32(murmur3.Sum32WithSeed([]byte(sb.String()), 0))
	return fmt.Sprintf("%d", h)
}

func probe(client *http.Client, url string) {
	if !strings.Contains(url, "://") {
		url = "http://" + url
	}
	resp, err := client.Get(url)
	if err != nil {
		fmt.Printf("%-40s  ERR    %v\n", url, err)
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))

	server := resp.Header.Get("Server")
	if server == "" {
		server = "-"
	}
	final := resp.Request.URL.String()

	fmt.Printf("%-40s  %d  server=%q  title=%q\n", url, resp.StatusCode, server, title(body))
	if final != url {
		fmt.Printf("    -> final: %s\n", final)
	}
	// Security headers worth noting by absence.
	for _, h := range []string{"Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options"} {
		state := "present"
		if resp.Header.Get(h) == "" {
			state = "MISSING"
		}
		fmt.Printf("    %-28s %s\n", h, state)
	}
	if fh := faviconHash(client, final); fh != "" {
		fmt.Printf("    favicon mmh3: %s\n", fh)
	}
}

func main() {
	if len(os.Args) != 2 {
		fmt.Printf("Usage: %s <urls.txt>\n", os.Args[0])
		os.Exit(1)
	}
	f, err := os.Open(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "open: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	client := mkClient()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		probe(client, line)
	}
}
