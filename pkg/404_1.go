package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"os/exec"
	"golang.org/x/time/rate"
)

// Rate limiting and HTTP client settings
var (
	wg      sync.WaitGroup
	limiter = rate.NewLimiter(5, 1) // 5 requests per second
	client  = &http.Client{
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 50,
			IdleConnTimeout:     30 * time.Second,
		},
	}
)

// Using sync.Map to avoid concurrent map access issues
var seenTimestamps sync.Map
var seenYears sync.Map

func main() {
	if len(os.Args) < 2 {
		fmt.Println("❌ Usage: go run 404_1.go <file_path>")
		return
	}

	selectedFilePath := os.Args[1]
	fmt.Printf("\n🚀 Running 404_1.go with target: %s\n", selectedFilePath)

	// Extract target folder (domain) and file base
	targetFolder, fileBase := extractTargetInfo(selectedFilePath)
	if targetFolder == "" || fileBase == "" {
		fmt.Println("❌ Error: Could not extract target information from path!")
		return
	}

	// Create 404_analysis folder
	rootAnalysisFolder := filepath.Join("404_analysis", targetFolder)
	if _, err := os.Stat(rootAnalysisFolder); os.IsNotExist(err) {
		err := os.MkdirAll(rootAnalysisFolder, 0755)
		if err != nil {
			fmt.Println("❌ Error creating 404_analysis folder:", err)
			return
		}
		fmt.Println("\n📁 404_analysis folder created in ~/recon-tool/")
	}

	// Read file contents
	urls, err := os.ReadFile(selectedFilePath)
	if err != nil {
		fmt.Println("❌ Error reading file:", err)
		return
	}

	urlList := strings.Split(strings.TrimSpace(string(urls)), "\n")
	if len(urlList) == 0 {
		fmt.Println("❌ No URLs found in file!")
		return
	}

	// Define output file names
	timestampFile := filepath.Join(rootAnalysisFolder, fmt.Sprintf("%s_%s_ymdhms1.txt", targetFolder, fileBase))
	yearFile := filepath.Join(rootAnalysisFolder, fmt.Sprintf("%s_%s_yr.txt", targetFolder, fileBase))

	for _, targetURL := range urlList {
		wg.Add(1)
		go func(url string) {
			defer wg.Done()
			limiter.Wait(context.Background()) // Rate limiting
			fmt.Printf("\n🌐 Checking URL: %s\n", url)
			checkWebArchive(url, timestampFile, yearFile)
		}(targetURL)
	}

	wg.Wait()
	fmt.Println("\n✅ All URLs checked!")

	// Trigger 404_2.go with correct format
	triggerScript2(targetFolder, fileBase)
}

// Extracts target folder name (domain) and file base (file type)
func extractTargetInfo(path string) (string, string) {
	// Normalize path separators
	path = filepath.ToSlash(path)
	
	// Ensure proper split
	parts := strings.Split(path, "/")
	if len(parts) < 3 {
		return "", "" // Invalid path structure
	}

	targetFolder := parts[1]  // Extract domain name
	fileName := parts[len(parts)-1]
	fileBase := strings.TrimSuffix(fileName, ".txt") // Extract file base

	return targetFolder, fileBase
}

// Fetches Web Archive snapshots and saves results
func checkWebArchive(targetURL, timestampFile, yearFile string) {
	apiURL := fmt.Sprintf("https://web.archive.org/__wb/sparkline?output=json&url=%s&collection=web", targetURL)

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		fmt.Println("❌ Error creating request:", err)
		return
	}

	// Set headers
        req.Header.Set("Host", "web.archive.org")
        req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0")
        req.Header.Set("Accept", "*/*")
        req.Header.Set("Accept-Language", "en-US,en;q=0.5")
        req.Header.Set("Accept-Encoding", "gzip, deflate, br")
        req.Header.Set("Referer", "https://web.archive.org/")
        req.Header.Set("Sec-Fetch-Dest", "empty")
        req.Header.Set("Sec-Fetch-Mode", "cors")
        req.Header.Set("Sec-Fetch-Site", "same-origin")
        req.Header.Set("Priority", "u=4")
        req.Header.Set("Te", "trailers")        
	client := &http.Client{Timeout: 20 * time.Second}

	// Retry logic
	maxRetries := 5
	var resp *http.Response
	for attempt := 1; attempt <= maxRetries; attempt++ {
		resp, err = client.Do(req)
		if err == nil {
			break // Success
		}
		fmt.Printf("❌ Attempt %d/%d failed: %v\n", attempt, maxRetries, err)
		time.Sleep(time.Duration(attempt) * 3 * time.Second) // Exponential backoff
	}

	if err != nil {
		fmt.Printf("❌ Request failed after %d retries: %v\n", maxRetries, err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Printf("⚠️ Skipping URL: %s (HTTP %d)\n", targetURL, resp.StatusCode)
		return
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("❌ Error reading response body:", err)
		return
	}

	var archiveResponse struct {
		FirstTS string            json:"first_ts"
		LastTS  string            json:"last_ts"
		Status  map[string]string json:"status"
	}

	if err := json.Unmarshal(body, &archiveResponse); err != nil {
		fmt.Println("❌ Error parsing JSON:", err)
		return
	}

	// Avoid duplicate timestamp URLs
	if archiveResponse.FirstTS == archiveResponse.LastTS {
		for _, status := range archiveResponse.Status {
			if strings.Contains(status, "2") {
				snapshotURL := fmt.Sprintf("https://web.archive.org/web/%sif_/%s", archiveResponse.FirstTS, targetURL)
				if _, exists := seenTimestamps.Load(snapshotURL); !exists {
					fmt.Printf("✅ 1 snap found for timeline %s:\n%s\n", archiveResponse.FirstTS[:4], snapshotURL)
					saveToFile(timestampFile, snapshotURL)
					seenTimestamps.Store(snapshotURL, true)
				}
				return
			}
		}
	} else {
		var years []string
		for year, status := range archiveResponse.Status {
			if strings.Contains(status, "2") {
				years = append(years, year)
			}
		}
		if len(years) > 0 {
			output := fmt.Sprintf("%s:[%s]", targetURL, strings.Join(years, ","))
			if _, exists := seenYears.Load(output); !exists {
				fmt.Println(output)
				saveToFile(yearFile, output)
				seenYears.Store(output, true)
			}
		}
	}
}

// Saves data to a file
func saveToFile(filename, data string) {
	file, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("❌ Error opening file:", err)
		return
	}
	defer file.Close()

	if _, err := file.WriteString(data + "\n"); err != nil {
		fmt.Println("❌ Error writing to file:", err)
	}
}

// Triggers 404_2.go with the correct argument format
func triggerScript2(target, fileBase string) {
	yearFile := fmt.Sprintf("404_analysis/%s/%s_%s_yr.txt", target, target, fileBase)
	fmt.Printf("\n💀 Extracting MMDD, process done silently, with this file: %s\n", yearFile)

	cmd := exec.Command("go", "run", "pkg/404_2.go", yearFile)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		fmt.Println("❌ Error running 404_2.go:", err)
	}
}
