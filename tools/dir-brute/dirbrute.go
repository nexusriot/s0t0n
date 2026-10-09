// dir-brute: wordlist-based web content discovery. Reports status, size and
// redirect target for each path. The active complement to cert-transparency /
// dns-recon brute. Authorized use only.
//
// Usage: dir-brute <base-url> [wordlist]   e.g. dir-brute https://host/
package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const workers = 30

func mkClient() *http.Client {
	return &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, DisableKeepAlives: true},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse // do not follow; report the redirect
		},
	}
}

func main() {
	if len(os.Args) < 2 {
		fmt.Printf("Usage: %s <base-url> [wordlist]\n", os.Args[0])
		os.Exit(1)
	}
	base := strings.TrimRight(os.Args[1], "/")
	if !strings.Contains(base, "://") {
		base = "http://" + base
	}
	wl := filepath.Join(filepath.Dir(os.Args[0]), "wordlist.txt")
	if len(os.Args) > 2 {
		wl = os.Args[2]
	}
	f, err := os.Open(wl)
	if err != nil {
		// fall back to a wordlist next to the source dir
		f, err = os.Open("wordlist.txt")
		if err != nil {
			fmt.Fprintf(os.Stderr, "open wordlist: %v\n", err)
			os.Exit(1)
		}
	}
	defer f.Close()

	var paths []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		p := strings.TrimSpace(sc.Text())
		if p != "" && !strings.HasPrefix(p, "#") {
			paths = append(paths, p)
		}
	}

	client := mkClient()
	jobs := make(chan string, len(paths))
	var wg sync.WaitGroup
	var mu sync.Mutex
	found := 0

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range jobs {
				url := base + "/" + p
				resp, err := client.Get(url)
				if err != nil {
					continue
				}
				n, _ := io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
				resp.Body.Close()
				// Report interesting statuses only.
				if resp.StatusCode == 404 {
					continue
				}
				mu.Lock()
				found++
				loc := resp.Header.Get("Location")
				extra := ""
				if loc != "" {
					extra = " -> " + loc
				}
				fmt.Printf("%-3d  %-30s  %6dB%s\n", resp.StatusCode, "/"+p, n, extra)
				mu.Unlock()
			}
		}()
	}
	for _, p := range paths {
		jobs <- p
	}
	close(jobs)
	wg.Wait()
	fmt.Printf("\n%d path(s) of interest.\n", found)
}
