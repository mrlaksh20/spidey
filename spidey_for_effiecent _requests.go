package main

import (
    "bufio"
    "context"
    "flag"
    "fmt"
    "io"
    "net/http"
    "net/url"
    "os"
    "sync"
    "sync/atomic"
    "time"
)

const (
    maxConcurrency = 10
    requestTimeout = 15 * time.Second
)

func main() {
    filePath := flag.String("f", "", "Path to file containing URLs (one per line)")
    flag.Parse()

    if *filePath == "" {
        fmt.Println("Please specify a file path using -f flag")
        os.Exit(1)
    }

    urls, err := readURLs(*filePath)
    if err != nil {
        fmt.Printf("Error reading URLs: %v\n", err)
        os.Exit(1)
    }

    client := newHTTPClient(requestTimeout)

    // Warm up TCP connections for all unique hosts first
    fmt.Println("Warming up connections to hosts...")
    if err := warmupConnections(client, urls); err != nil {
        fmt.Printf("Warning: error during warmup: %v\n", err)
    }
    fmt.Println("Warmup done. Starting requests...")

    var wg sync.WaitGroup
    sem := make(chan struct{}, maxConcurrency) // semaphore to limit concurrency

    var successCount int64
    var errorCount int64

    for _, urlStr := range urls {
        wg.Add(1)
        sem <- struct{}{}

        go func(u string) {
            defer wg.Done()
            defer func() { <-sem }()

            body, status, err := fetchURL(client, u)
            if err != nil {
                fmt.Printf("[ERROR] %s - %v\n", u, err)
                atomic.AddInt64(&errorCount, 1)
                return
            }

            atomic.AddInt64(&successCount, 1)

            red := "\033[31m"
            reset := "\033[0m"
            fmt.Printf("URL: %s%s%s\nStatus: %d\nBody Snippet:\n%s\n\n", red, u, reset, status, body)

        }(urlStr)
    }

    wg.Wait()

    total := len(urls)
    fmt.Printf("\nSummary: Processed %d URLs\n", total)
    fmt.Printf("Successful: %d\n", atomic.LoadInt64(&successCount))
    fmt.Printf("Errors: %d\n", atomic.LoadInt64(&errorCount))
}

// warmupConnections performs a sequential HEAD request to each unique host to establish TCP connections
func warmupConnections(client *http.Client, urls []string) error {
    uniqueHosts := make(map[string]struct{})
    for _, u := range urls {
        host, err := extractHost(u)
        if err != nil {
            // skip malformed URLs
            continue
        }
        uniqueHosts[host] = struct{}{}
    }

    for host := range uniqueHosts {
        warmupURL := "https://" + host + "/"
        ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
        req, err := http.NewRequestWithContext(ctx, http.MethodHead, warmupURL, nil)
        if err != nil {
            cancel()
            continue
        }
        req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; spidey/1.0)")

        resp, err := client.Do(req)
        cancel()
        if err != nil {
            fmt.Printf("[Warmup Warning] Could not connect to %s: %v\n", warmupURL, err)
            continue
        }

        // Drain and close to allow connection reuse
        io.Copy(io.Discard, resp.Body)
        resp.Body.Close()
    }

    return nil
}

func extractHost(rawurl string) (string, error) {
    u, err := url.Parse(rawurl)
    if err != nil {
        return "", err
    }
    return u.Host, nil
}

func readURLs(path string) ([]string, error) {
    f, err := os.Open(path)
    if err != nil {
        return nil, err
    }
    defer f.Close()

    var urls []string
    scanner := bufio.NewScanner(f)
    for scanner.Scan() {
        line := scanner.Text()
        if line != "" {
            urls = append(urls, line)
        }
    }
    if err := scanner.Err(); err != nil {
        return nil, err
    }
    return urls, nil
}

func newHTTPClient(timeout time.Duration) *http.Client {
    return &http.Client{
        Timeout: timeout,
        Transport: &http.Transport{
            MaxIdleConns:        100,
            MaxIdleConnsPerHost: 20,
            IdleConnTimeout:     90 * time.Second,
        },
    }
}

func fetchURL(client *http.Client, url string) (string, int, error) {
    ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
    defer cancel()

    req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
    if err != nil {
        return "", 0, err
    }

    req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; spidey/1.0)")

    resp, err := client.Do(req)
    if err != nil {
        return "", 0, err
    }
    defer resp.Body.Close()

    bodyBytes, err := io.ReadAll(resp.Body)
    if err != nil {
        return "", resp.StatusCode, err
    }

    return string(bodyBytes), resp.StatusCode, nil
}
