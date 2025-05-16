package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"net/http"
	"fmt"
	"io/ioutil"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	MaxWorkers = 10
	MaxRetries = 3
	SnapDir    = "snapurls"
	RegexFile  = "regex_patterns/regex.json"
	ReportDir  = "reports"
	RetryDelay = 3 * time.Second
)

type CompiledPattern struct {
	Name  string
	Regex *regexp.Regexp
}

type ScanResult struct {
	URL      string            `json:"url"`
	Findings map[string]string `json:"findings"`
}

func loadRegexPatterns() ([]CompiledPattern, error) {
	data, err := ioutil.ReadFile(RegexFile)
	if err != nil {
		return nil, err
	}
	var rawPatterns map[string]string
	err = json.Unmarshal(data, &rawPatterns)
	if err != nil {
		return nil, err
	}

	var compiled []CompiledPattern
	for name, pattern := range rawPatterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			fmt.Printf("❌ Failed to compile pattern [%s]: %v\n", name, err)
			continue
		}
		compiled = append(compiled, CompiledPattern{Name: name, Regex: re})
	}
	return compiled, nil
}


var customClient = &http.Client{
	Timeout: 5 * time.Second,
	Transport: &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		MaxConnsPerHost:     100,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  false,
	},
}

func fetchResponse(url string) (string, error) {
	for i := 0; i < MaxRetries; i++ {
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (SpideyReconTool)")

		resp, err := customClient.Do(req)
		if err == nil && resp.StatusCode == 200 {
			defer resp.Body.Close()
			body, _ := ioutil.ReadAll(resp.Body)
			return string(body), nil
		}

		if resp != nil {
			resp.Body.Close()
		}
		time.Sleep(RetryDelay)
	}
	return "", fmt.Errorf("💥 failed after retries: %s", url)
}

func scanContent(url, content string, patterns []CompiledPattern) *ScanResult {
	result := &ScanResult{URL: url, Findings: make(map[string]string)}
	for _, p := range patterns {
		matches := p.Regex.FindStringSubmatch(content)
		if len(matches) > 0 {
			trimmed := []string{}
			for _, match := range matches {
				if len(match) > 100 {
					match = match[:100] + "..."
				}
				trimmed = append(trimmed, match)
			}
			result.Findings[p.Name] = strings.Join(trimmed, ", ")
		}
	}
	if len(result.Findings) > 0 {
		return result
	}
	return nil
}

func printLeak(workerID int, url string, findings map[string]string) {
	bold := "\033[1m"
	yellow := "\033[33m"
	cyan := "\033[38;5;51m"
	reset := "\033[0m"
	red := "\033[31m"

	fmt.Printf("%s[Worker %d] 🐷 Leak Found:%s %s%s%s\n", bold+cyan, workerID, reset, bold+red, url, reset)
	for key, value := range findings {
		fmt.Printf("    🔎 %s%s%s: %s%s%s\n", yellow, key, reset, bold, value, reset)
	}
}

func worker(id int, urls <-chan string, results chan<- *ScanResult, patterns []CompiledPattern, wg *sync.WaitGroup) {
	defer wg.Done()
	for url := range urls {
		content, err := fetchResponse(url)
		if err != nil {
			fmt.Printf("[Worker %d] ❌ Failed: %s\n", id, url)
			continue
		}
		result := scanContent(url, content, patterns)
		if result != nil {
			printLeak(id, url, result.Findings)
			results <- result
		}
	}
}

func processFile(filename string, patterns []CompiledPattern) {
	filePath := fmt.Sprintf("%s/%s", SnapDir, filename)
	file, err := os.Open(filePath)
	if err != nil {
		fmt.Printf("❌ Error opening %s: %v\n", filename, err)
		return
	}
	defer file.Close()

	var urls []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		urls = append(urls, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		fmt.Printf("❌ Error reading %s: %v\n", filename, err)
		return
	}

	fmt.Printf("🚀 Scanning %s (Total: %d URLs)\n", filename, len(urls))

	urlChan := make(chan string, len(urls))
	resultsChan := make(chan *ScanResult, len(urls))
	var wg sync.WaitGroup

	for i := 0; i < MaxWorkers; i++ {
		wg.Add(1)
		go worker(i, urlChan, resultsChan, patterns, &wg)
	}

	for _, url := range urls {
		urlChan <- url
	}
	close(urlChan)

	wg.Wait()
	close(resultsChan)

	var foundLeaks []*ScanResult
	for res := range resultsChan {
		foundLeaks = append(foundLeaks, res)
	}

	if len(foundLeaks) > 0 {
		saveResults(filename, foundLeaks)
	} else {
		fmt.Printf("✅ No leaks found in %s\n", filename)
	}
}

func saveResults(filename string, results []*ScanResult) {
	if _, err := os.Stat(ReportDir); os.IsNotExist(err) {
		os.Mkdir(ReportDir, 0755)
	}
	outputFile := fmt.Sprintf("%s/%s_results.json", ReportDir, strings.TrimSuffix(filename, ".txt"))
	data, _ := json.MarshalIndent(results, "", "  ")
	ioutil.WriteFile(outputFile, data, 0644)
	fmt.Printf("📄 Results saved: %s\n", outputFile)
}

func selectFiles() []string {
	files, err := ioutil.ReadDir(SnapDir)
	if err != nil {
		fmt.Println("❌ Error reading snapurls directory:", err)
		return nil
	}

	fmt.Println("\nAvailable Targets:")
	var availableFiles []string
	for i, file := range files {
		if strings.HasSuffix(file.Name(), ".txt") {
			fmt.Printf("%d. %s\n", i+1, file.Name())
			availableFiles = append(availableFiles, file.Name())
		}
	}

	fmt.Print("\nSelect files to scan (comma-separated numbers or 'all'): ")
	var input string
	fmt.Scanln(&input)

	if input == "all" {
		return availableFiles
	}

	choices := strings.Split(input, ",")
	var selectedFiles []string
	for _, choice := range choices {
		index := strings.TrimSpace(choice)
		i := -1
		fmt.Sscanf(index, "%d", &i)
		if i > 0 && i <= len(availableFiles) {
			selectedFiles = append(selectedFiles, availableFiles[i-1])
		}
	}
	return selectedFiles
}

func main() {
	cliFiles := flag.String("f", "", "Comma-separated list of files to scan (inside snapurls dir)")
	flag.Parse()

	patterns, err := loadRegexPatterns()
	if err != nil {
		fmt.Println("❌ Error loading regex patterns:", err)
		return
	}

	var filesToScan []string
	if *cliFiles != "" {
		filesToScan = strings.Split(*cliFiles, ",")
	} else {
		filesToScan = selectFiles()
	}

	if len(filesToScan) == 0 {
		fmt.Println("❌ No valid files selected. Exiting.")
		return
	}

	for _, file := range filesToScan {
		processFile(file, patterns)
	}
	fmt.Println("...")
}
