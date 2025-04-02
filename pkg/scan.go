package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	MaxWorkers  = 15 // Optimal worker threads (10-15)
	MaxRetries  = 3  // Retry failed requests up to 3 times
	SnapDir     = "snapsurls"
	RegexFile   = "regex_patterns/regex.json"
	ReportDir   = "reports"
	RetryDelay  = 3 * time.Second // Delay before retrying failed requests
)

// RegexPatterns struct to store loaded regex patterns
type RegexPatterns map[string]string

// ScanResult stores the findings per URL
type ScanResult struct {
	URL      string            `json:"url"`
	Findings map[string]string `json:"findings"`
}

// Load regex patterns from regex1.json
func loadRegexPatterns() (RegexPatterns, error) {
	data, err := ioutil.ReadFile(RegexFile)
	if err != nil {
		return nil, err
	}
	var patterns RegexPatterns
	err = json.Unmarshal(data, &patterns)
	if err != nil {
		return nil, err
	}
	return patterns, nil
}

// Fetch full response with retries
func fetchResponse(url string) (string, error) {
	client := &http.Client{
		Timeout: 10 * time.Second, // Ensure full response loads
	}
	for i := 0; i < MaxRetries; i++ {
		resp, err := client.Get(url)
		if err == nil && resp.StatusCode == 200 {
			body, _ := ioutil.ReadAll(resp.Body)
			resp.Body.Close()
			return string(body), nil
		}
		if i < MaxRetries-1 {
			time.Sleep(RetryDelay) // Wait before retrying
		}
	}
	return "", fmt.Errorf("failed after %d retries", MaxRetries)
}

// Scan URL content for leaks
func scanContent(url, content string, patterns RegexPatterns) *ScanResult {
	result := &ScanResult{URL: url, Findings: make(map[string]string)}
	for key, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindStringSubmatch(content)
		if len(matches) > 0 {
			// Limit match length to 100 chars to avoid huge dumps
			trimmedMatches := []string{}
			for _, match := range matches {
				if len(match) > 100 {
					match = match[:100] + "..." // Trim and add '...'
				}
				trimmedMatches = append(trimmedMatches, match)
			}
			result.Findings[key] = strings.Join(trimmedMatches, ", ")
		}
	}

	if len(result.Findings) > 0 {
		return result
	}
	return nil
}

// Print leaks with bold & color
func printLeak(workerID int, url string, findings map[string]string) {
	bold := "\033[1m"
	yellow := "\033[33m"
	cyan := "\033[38;5;51m"
	reset := "\033[0m"
        red := "\033[31m"

	// Print Leak Found with Bold & Yellow
	fmt.Printf("%s[Worker %d] 🐷 Leak Found:%s %s%s%s\n", bold+cyan, workerID, reset, bold+red, url, reset)

	// Print Findings with Cyan
	for key, value := range findings {
		fmt.Printf("    🔎 %s%s%s: %s%s%s\n", yellow, key, reset, bold, value, reset)
	}
}

// Worker function to process URLs
func worker(id int, urls <-chan string, results chan<- *ScanResult, patterns RegexPatterns, wg *sync.WaitGroup) {
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

// Process a single file
func processFile(filename string, patterns RegexPatterns) {
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

	// Start workers
	urlChan := make(chan string, len(urls))
	resultsChan := make(chan *ScanResult, len(urls))
	var wg sync.WaitGroup

	for i := 0; i < MaxWorkers; i++ {
		wg.Add(1)
		go worker(i, urlChan, resultsChan, patterns, &wg)
	}

	// Send URLs to workers
	for _, url := range urls {
		urlChan <- url
	}
	close(urlChan)

	// Wait for workers to finish
	wg.Wait()
	close(resultsChan)

	// Collect results
	var foundLeaks []*ScanResult
	for res := range resultsChan {
		foundLeaks = append(foundLeaks, res)
	}

	// Save results
	if len(foundLeaks) > 0 {
		saveResults(filename, foundLeaks)
	} else {
		fmt.Printf("✅ No leaks found in %s\n", filename)
	}
}

// Save scan results as JSON
func saveResults(filename string, results []*ScanResult) {
	if _, err := os.Stat(ReportDir); os.IsNotExist(err) {
		os.Mkdir(ReportDir, 0755)
	}
	outputFile := fmt.Sprintf("%s/%s_results.json", ReportDir, strings.TrimSuffix(filename, ".txt"))
	data, _ := json.MarshalIndent(results, "", "  ")
	ioutil.WriteFile(outputFile, data, 0644)
	fmt.Printf("📄 Results saved: %s\n", outputFile)
}

// Select files to scan
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

// Main function
func main() {
	patterns, err := loadRegexPatterns()
	if err != nil {
		fmt.Println("❌ Error loading regex patterns:", err)
		return
	}

	filesToScan := selectFiles()
	if len(filesToScan) == 0 {
		fmt.Println("❌ No valid files selected. Exiting.")
		return
	}

	for _, file := range filesToScan {
		processFile(file, patterns)
	}
	fmt.Println("🎉 Scan completed!")
}
