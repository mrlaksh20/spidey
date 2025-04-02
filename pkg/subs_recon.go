package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

const urlscanAPIKey = "fc0c1e64-a4c8-42e0-876e-a573ccbbc1a6"

var validSubdomain = regexp.MustCompile(`^[a-zA-Z0-9.-]+\.[a-zA-Z]+$`)

func cleanSubdomain(sub string) string {
	sub = strings.TrimSpace(sub)
	sub = strings.TrimPrefix(sub, "*.")
	if validSubdomain.MatchString(sub) {
		return sub
	}
	return ""
}

func fetchCRTSubdomains(target string, results chan<- string) {
	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", target)
	for retries := 0; retries < 3; retries++ {
		resp, err := http.Get(url)
		if err != nil {
			fmt.Println("[crt.sh] Error:", err)
			time.Sleep(2 * time.Second)
			continue
		}
		defer resp.Body.Close()

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			fmt.Println("[crt.sh] Read error:", err)
			return
		}

		var data []map[string]interface{}
		if err := json.Unmarshal(body, &data); err != nil {
			fmt.Println("[crt.sh] JSON error:", err)
			return
		}

		for _, entry := range data {
			if name, ok := entry["name_value"].(string); ok {
				subs := strings.Split(name, "\n")
				for _, sub := range subs {
					if clean := cleanSubdomain(sub); clean != "" {
						results <- clean
					}
				}
			}
		}
		return
	}
}

func fetchHackerTargetSubdomains(target string, results chan<- string) {
	url := fmt.Sprintf("https://api.hackertarget.com/hostsearch/?q=%s", target)
	resp, err := http.Get(url)
	if err != nil {
		fmt.Println("[HackerTarget] Error:", err)
		return
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("[HackerTarget] Read error:", err)
		return
	}

	lines := strings.Split(string(body), "\n")
	for _, line := range lines {
		parts := strings.Split(line, ",")
		if len(parts) > 0 {
			if clean := cleanSubdomain(parts[0]); clean != "" {
				results <- clean
			}
		}
	}
}

func fetchRapidDNSSubdomains(target string, results chan<- string) {
	url := fmt.Sprintf("https://rapiddns.io/subdomain/%s?full=1", target)
	resp, err := http.Get(url)
	if err != nil {
		fmt.Println("[RapidDNS] Error:", err)
		return
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("[RapidDNS] Read error:", err)
		return
	}

	lines := strings.Split(string(body), "\n")
	for _, line := range lines {
		if clean := cleanSubdomain(line); clean != "" {
			results <- clean
		}
	}
}

func fetchUrlscanSubdomains(target string, results chan<- string) {
	url := fmt.Sprintf("https://urlscan.io/api/v1/search/?q=domain:%s", target)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Println("[urlscan.io] Request error:", err)
		return
	}
	req.Header.Set("API-Key", urlscanAPIKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Println("[urlscan.io] Error:", err)
		return
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("[urlscan.io] Read error:", err)
		return
	}

	var data map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		fmt.Println("[urlscan.io] JSON error:", err)
		return
	}

	if resultsArr, ok := data["results"].([]interface{}); ok {
		for _, result := range resultsArr {
			if resultMap, valid := result.(map[string]interface{}); valid {
				if page, exists := resultMap["page"].(map[string]interface{}); exists {
					if domain, ok := page["domain"].(string); ok {
						if clean := cleanSubdomain(domain); clean != "" {
							results <- clean
						}
					}
				}
			}
		}
	}
}

func main() {
	var target string
	fmt.Print("Enter Your Target🕸️ >>> ")
	fmt.Scanln(&target)

	results := make(chan string)
	var wg sync.WaitGroup

	sources := []func(string, chan<- string){
		fetchCRTSubdomains,
		fetchHackerTargetSubdomains,
		fetchRapidDNSSubdomains,
		fetchUrlscanSubdomains,
	}

	for _, source := range sources {
		wg.Add(1)
		go func(sourceFunc func(string, chan<- string)) {
			defer wg.Done()
			sourceFunc(target, results)
		}(source)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	uniqueSubs := make(map[string]struct{})

	for sub := range results {
		uniqueSubs[sub] = struct{}{}
	}

	file, err := ioutil.TempFile(".", "subs.txt")
	if err != nil {
		fmt.Println("File write error:", err)
		return
	}
	defer file.Close()

	count := 0
	for sub := range uniqueSubs {
		file.WriteString(sub + "\n")
		count++
	}

	fmt.Printf("%d unique subdomains saved to %s\n", count, file.Name())
}
