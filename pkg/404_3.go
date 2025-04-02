package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Global variables
var timestampFile string
var targetFolder string
var rateLimiter = time.NewTicker(100 * time.Millisecond) // Adjust delay between requests
var semaphore = make(chan struct{}, 100)                 // Limit concurrency to 50 goroutines

// Wayback Machine JSON response structure
type WaybackResponse struct {
	Items [][]json.RawMessage `json:"items"`
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run 404_3.go <timestamp_file>")
		return
	}

	// Set global variables
	timestampFile = os.Args[1]
	targetFolder = filepath.Base(filepath.Dir(timestampFile)) // Extract target folder name

	processFile(timestampFile)
}

func processFile(tsFile string) {
	// Extract filename safely
	yearFileBase := filepath.Base(tsFile)
	yearFileDir := filepath.Dir(tsFile)

	pathParts := strings.Split(yearFileBase, "_")
	if len(pathParts) < 2 {
		fmt.Printf("❌ Error: Invalid file format: %s\n", yearFileBase)
		return
	}

	targetFileName := strings.TrimSuffix(yearFileBase, "_ts.txt")

	// Define output files
	ymdhms2File := filepath.Join(yearFileDir, fmt.Sprintf("%s_ymdhms2.txt", targetFileName))
	ymdhms1File := filepath.Join(yearFileDir, fmt.Sprintf("%s_ymdhms1.txt", targetFileName))
	scanFolder := "snapsurls"
	scanFile := filepath.Join(scanFolder, fmt.Sprintf("%s_scan.txt", targetFileName))

	// Create scanFolder if it doesn't exist
	if _, err := os.Stat(scanFolder); os.IsNotExist(err) {
		os.Mkdir(scanFolder, 0755)
	}

	// Open tsFile and process each line concurrently
	file, err := os.Open(tsFile)
	if err != nil {
		fmt.Printf("❌ Error opening file %s: %v\n", tsFile, err)
		return
	}
	defer file.Close()

	// Output file for extracted URLs
	ymdhms2Output, err := os.Create(ymdhms2File)
	if err != nil {
		fmt.Printf("❌ Error creating %s: %v\n", ymdhms2File, err)
		return
	}
	defer ymdhms2Output.Close()

	scanner := bufio.NewScanner(file)
	var wg sync.WaitGroup

	// Process each line concurrently
	for scanner.Scan() {
		line := scanner.Text()
		url, dates := parseLine(line)
		if url == "" || len(dates) == 0 {
			continue
		}

		for _, date := range dates {
			wg.Add(1)
			semaphore <- struct{}{} // Acquire semaphore
			go func(url, date string) {
				defer wg.Done()
				defer func() { <-semaphore }() // Release semaphore

				timestamps := fetchTimestampsWithRetry(url, date, 5) // Retry logic applied
				for _, ts := range timestamps {
					finalURL := fmt.Sprintf("https://web.archive.org/web/%s%sif_/%s", date, ts, url)
					ymdhms2Output.WriteString(finalURL + "\n") // Save in _ymdhms2.txt
				}
			}(url, date)
		}
	}

	wg.Wait() // Wait for all goroutines to complete

	// Combine _ymdhms1.txt and _ymdhms2.txt into _scan.txt
	combineFiles(ymdhms1File, ymdhms2File, scanFile)
	fmt.Printf("✅ Combined archived URLs saved: %s\n", scanFile)
}

// Parse line to extract URL and timestamps
func parseLine(line string) (string, []string) {
	re := regexp.MustCompile(`(https?://[^\s]+):\{\[([0-9,]+)\]\}`)
	matches := re.FindStringSubmatch(line)

	if len(matches) != 3 {
		return "", nil
	}

	url := matches[1]
	dates := strings.Split(matches[2], ",")
	return url, dates
}

// Fetch full timestamps from Wayback Machine with retries
func fetchTimestampsWithRetry(url, date string, maxRetries int) []string {
	for attempt := 1; attempt <= maxRetries; attempt++ {
		timestamps := fetchTimestamps(url, date)
		if len(timestamps) > 0 {
			return timestamps
		}

		fmt.Printf("⚠️ Retry %d/%d for %s...\n", attempt, maxRetries, url)
		time.Sleep(500 * time.Millisecond) // Wait before retrying
	}

	fmt.Printf("❌ Failed to fetch timestamps for %s after %d attempts.\n", url, maxRetries)
	return nil
}

// Fetch full timestamps from Wayback Machine (with rate limiting)
func fetchTimestamps(url, date string) []string {
	apiURL := fmt.Sprintf("https://web.archive.org/__wb/calendarcaptures/2?url=%s&date=%s", url, date)

	// Wait for rate limiter before making the request
	<-rateLimiter.C

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		fmt.Printf("❌ Error creating request: %v\n", err)
		return nil
	}

	// Headers
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Referer", "https://web.archive.org/web/")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Printf("❌ Error making request for %s: %v\n", url, err)
		return nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("❌ Error reading response body: %v\n", err)
		return nil
	}

	var wayback WaybackResponse
	if err := json.Unmarshal(body, &wayback); err != nil {
		fmt.Printf("❌ JSON parsing error for %s: %v\nResponse: %s\n", url, err, string(body))
		return nil
	}

	var timestamps []string
	for _, entry := range wayback.Items {
		if len(entry) < 2 {
			continue
		}

		var ts int
		if err := json.Unmarshal(entry[0], &ts); err != nil {
			var tsStr string
			if err := json.Unmarshal(entry[0], &tsStr); err != nil {
				fmt.Printf("❌ Skipping invalid timestamp format: %v\n", entry[0])
				continue
			}
			fmt.Sscanf(tsStr, "%d", &ts)
		}

		var status int
		if err := json.Unmarshal(entry[1], &status); err != nil {
			var statusStr string
			if err := json.Unmarshal(entry[1], &statusStr); err != nil || statusStr != "-" {
				continue
			}
		} else {
			if status != 200 {
				continue
			}
		}

		tsFormatted := fmt.Sprintf("%06d", ts)
		timestamps = append(timestamps, tsFormatted)
	}

	return timestamps
}

// Combine two files into one
func combineFiles(file1, file2, outputFile string) {
	outFile, err := os.Create(outputFile)
	if err != nil {
		fmt.Printf("❌ Error creating %s: %v\n", outputFile, err)
		return
	}
	defer outFile.Close()

	appendFileContent(file1, outFile)
	appendFileContent(file2, outFile)
}

// Append file content to another file
func appendFileContent(srcFile string, destFile *os.File) {
	file, err := os.Open(srcFile)
	if err != nil {
		fmt.Printf("⚠️ Warning: Could not open %s (might not exist)\n", srcFile)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		destFile.WriteString(scanner.Text() + "\n")
	}
}
