// tech-detect: fingerprint server technology from HTTP response headers,
// cookies, body markers and the favicon mmh3 hash. Authorized use only.
//
// Usage: tech-detect <url>
package main

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"

	"github.com/spaolacci/murmur3"
)

type sig struct {
	name    string
	header  string // header name to check (optional)
	pattern *regexp.Regexp
	body    bool // match against body instead of header
}

var sigs = []sig{
	{"nginx", "Server", regexp.MustCompile(`(?i)nginx`), false},
	{"Apache", "Server", regexp.MustCompile(`(?i)apache`), false},
	{"IIS", "Server", regexp.MustCompile(`(?i)iis|microsoft`), false},
	{"Cloudflare", "Server", regexp.MustCompile(`(?i)cloudflare`), false},
	{"PHP", "X-Powered-By", regexp.MustCompile(`(?i)php`), false},
	{"ASP.NET", "X-Powered-By", regexp.MustCompile(`(?i)asp\.net`), false},
	{"Express", "X-Powered-By", regexp.MustCompile(`(?i)express`), false},
	{"WordPress", "", regexp.MustCompile(`(?i)wp-content|wp-includes`), true},
	{"Drupal", "", regexp.MustCompile(`(?i)Drupal.settings|/sites/default/files`), true},
	{"Joomla", "", regexp.MustCompile(`(?i)/media/jui/|Joomla`), true},
	{"React", "", regexp.MustCompile(`(?i)__REACT_DEVTOOLS|data-reactroot`), true},
	{"Vue.js", "", regexp.MustCompile(`(?i)data-v-[0-9a-f]{8}|__vue__`), true},
}

func main() {
	if len(os.Args) != 2 {
		fmt.Printf("Usage: %s <url>\n", os.Args[0])
		os.Exit(1)
	}
	url := os.Args[1]
	if !strings.Contains(url, "://") {
		url = "http://" + url
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	resp, err := client.Get(url)
	if err != nil {
		fmt.Fprintf(os.Stderr, "get: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	fmt.Printf("%s  [%d]\n", url, resp.StatusCode)
	if s := resp.Header.Get("Server"); s != "" {
		fmt.Printf("  Server: %s\n", s)
	}
	if p := resp.Header.Get("X-Powered-By"); p != "" {
		fmt.Printf("  X-Powered-By: %s\n", p)
	}

	var hits []string
	for _, s := range sigs {
		var hay string
		if s.body {
			hay = string(body)
		} else if s.header != "" {
			hay = resp.Header.Get(s.header)
		}
		if hay != "" && s.pattern.MatchString(hay) {
			hits = append(hits, s.name)
		}
	}
	// Cookie-based hints.
	for _, c := range resp.Cookies() {
		switch {
		case strings.HasPrefix(c.Name, "wordpress_"), c.Name == "wp-settings":
			hits = append(hits, "WordPress(cookie)")
		case c.Name == "PHPSESSID":
			hits = append(hits, "PHP(cookie)")
		case c.Name == "JSESSIONID":
			hits = append(hits, "Java/JSP(cookie)")
		case c.Name == "laravel_session":
			hits = append(hits, "Laravel(cookie)")
		}
	}

	if fh := faviconHash(client, url); fh != "" {
		fmt.Printf("  favicon mmh3: %s\n", fh)
	}
	fmt.Printf("  tech: %s\n", strings.Join(dedupe(hits), ", "))
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return []string{"(none matched)"}
	}
	return out
}

func faviconHash(client *http.Client, base string) string {
	u := strings.TrimRight(base, "/") + "/favicon.ico"
	resp, err := client.Get(u)
	if err != nil || resp.StatusCode != 200 {
		return ""
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if len(raw) == 0 {
		return ""
	}
	b64 := base64.StdEncoding.EncodeToString(raw)
	var sb strings.Builder
	for i := 0; i < len(b64); i += 76 {
		end := i + 76
		if end > len(b64) {
			end = len(b64)
		}
		sb.WriteString(b64[i:end])
		sb.WriteByte('\n')
	}
	return fmt.Sprintf("%d", int32(murmur3.Sum32WithSeed([]byte(sb.String()), 0)))
}
