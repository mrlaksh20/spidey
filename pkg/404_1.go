// 📦 File: 404_1.go
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

var (
	wg            sync.WaitGroup
	limiter       = rate.NewLimiter(10, 1) // upped rate limit for smoother high-thread load
	client        = &http.Client{Timeout: 20 * time.Second}
	seenTimestamps sync.Map
	seenYears     sync.Map
	threadPool    = 10 // concurrency level
)

func main() {
	flagSet := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	fileFlags := flagSet.String("f", "", "Comma-separated list of files to process")
	flagSet.Parse(os.Args[2:])
	targetPath := os.Args[1]

	fileList := []string{}
	if *fileFlags != "" {
		fmt.Println("🧩 Multiple File Mode Activated")
		files := strings.Split(*fileFlags, ",")
		for _, file := range files {
			trimmed := strings.TrimSpace(file)
			if trimmed != "" {
				fileList = append(fileList, trimmed)
			}
		}
		if len(fileList) == 0 {
			fmt.Println("❌ No valid files specified in -f flag.")
			return
		}
		processMultipleFiles(targetPath, fileList)
	} else {
		fmt.Printf("📁 Single File Mode: %s\n", targetPath)
		runYearExtraction(targetPath)
	// Trigger 404_2.go manually for single file mode
	target, base := extractTargetInfo(targetPath)
	yrFile := filepath.Join("404_analysis", target, fmt.Sprintf("%s_%s_yr.txt", target, base))
	fmt.Printf("\n🔥 Running 404_2.go with: %s\n", yrFile)
	cmd := exec.Command("go", "run", "pkg/404_2.go", yrFile)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
	fmt.Printf("❌ Error running 404_2.go on %s: %v\n", yrFile, err)
	}
	}
}

// 🔁 MULTIPLE FILE PROCESSING
func processMultipleFiles(folder string, files []string) {
	var yearFiles []string

	for _, f := range files {
		path := filepath.Join(folder, f+".txt")
		fmt.Printf("\n📂 Processing file: %s\n", path)
		runYearExtraction(path)

		// Store generated _yr.txt for later trigger
		target, base := extractTargetInfo(path)
		yrFile := filepath.Join("404_analysis", target, fmt.Sprintf("%s_%s_yr.txt", target, base))
		yearFiles = append(yearFiles, yrFile)
	}

	// Trigger 404_2.go on all generated _yr.txt files with delay
	fmt.Println("\n🔁 Triggering 404_2.go for all _yr.txt files...")
	for _, yrFile := range yearFiles {
		fmt.Printf("\n🔥 Running 404_2.go with: %s\n", yrFile)
		cmd := exec.Command("go", "run", "pkg/404_2.go", yrFile)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Printf("❌ Error running 404_2.go on %s: %v\n", yrFile, err)
		}
		time.Sleep(3 * time.Second) // ⏱️ delay between triggers
	}
}

// 💥 SNAPSHOT CHECK WITH WORKER POOL
func runYearExtraction(filePath string) {
	targetFolder, fileBase := extractTargetInfo(filePath)
	if targetFolder == "" || fileBase == "" {
		fmt.Println("❌ Could not parse target info")
		return
	}

	rootAnalysisFolder := filepath.Join("404_analysis", targetFolder)
	_ = os.MkdirAll(rootAnalysisFolder, 0755)

	urls, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Printf("❌ Read error: %v\n", err)
		return
	}
	lines := strings.Split(strings.TrimSpace(string(urls)), "\n")
	if len(lines) == 0 {
		fmt.Println("❌ No URLs in file!")
		return
	}

	timestampFile := filepath.Join(rootAnalysisFolder, fmt.Sprintf("%s_%s_ymdhms1.txt", targetFolder, fileBase))
	yearFile := filepath.Join(rootAnalysisFolder, fmt.Sprintf("%s_%s_yr.txt", targetFolder, fileBase))

	urlChan := make(chan string, threadPool)

	// Spin up worker goroutines
	for i := 0; i < threadPool; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for u := range urlChan {
				limiter.Wait(context.Background())
				fmt.Printf("🌐 Checking: %s\n", u)
				checkWebArchive(u, timestampFile, yearFile)
			}
		}()
	}

	for _, url := range lines {
		urlChan <- url
	}
	close(urlChan)
	wg.Wait()
	fmt.Println("✅ Done:", filePath)
}

func extractTargetInfo(path string) (string, string) {
	path = filepath.ToSlash(path)
	parts := strings.Split(path, "/")
	if len(parts) < 3 {
		return "", ""
	}
	targetFolder := parts[1]
	file := filepath.Base(path)
	fileBase := strings.TrimSuffix(file, ".txt")
	return targetFolder, fileBase
}

func checkWebArchive(targetURL, timestampFile, yearFile string) {
	apiURL := fmt.Sprintf("https://web.archive.org/__wb/sparkline?output=json&url=%s&collection=web", targetURL)
	req, _ := http.NewRequest("GET", apiURL, nil)
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

	var resp *http.Response
	var err error
	for i := 1; i <= 5; i++ {
		resp, err = client.Do(req)
		if err == nil {
			break
		}
		fmt.Printf("⚠️ Retry %d: %v\n", i, err)
		time.Sleep(time.Duration(i) * 3 * time.Second)
	}
	if err != nil {
		fmt.Println("❌ Final failure:", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Printf("⚠️ Bad response: %d\n", resp.StatusCode)
		return
	}

	body, _ := io.ReadAll(resp.Body)
	var archiveResponse struct {
		FirstTS string            `json:"first_ts"`
		LastTS  string            `json:"last_ts"`
		Status  map[string]string `json:"status"`
	}
	if err := json.Unmarshal(body, &archiveResponse); err != nil {
		fmt.Println("❌ JSON parse error:", err)
		return
	}

	if archiveResponse.FirstTS == archiveResponse.LastTS {
	for _, status := range archiveResponse.Status {
		if strings.Contains(status, "2") {
			snap := fmt.Sprintf("https://web.archive.org/web/%sif_/%s", archiveResponse.FirstTS, targetURL)
			if _, ok := seenTimestamps.Load(snap); !ok {
				saveToFile(timestampFile, snap)
				fmt.Printf("🧭 1 archive snapshot found: %s\n", snap) // 💬 ADDED THIS
				seenTimestamps.Store(snap, true)
			}
		}
	}
	} else {
	var years []string
	for yr, status := range archiveResponse.Status {
		if strings.Contains(status, "2") {
			years = append(years, yr)
		}
	}
	if len(years) > 0 {
		line := fmt.Sprintf("%s:[%s]", targetURL, strings.Join(years, ","))
		if _, ok := seenYears.Load(line); !ok {
			saveToFile(yearFile, line)
			fmt.Printf("📚 Archive years found for %s: [%s]\n", targetURL, strings.Join(years, ","))
			seenYears.Store(line, true)
		}
	}
}


}

func saveToFile(file, data string) {
	f, err := os.OpenFile(file, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("❌ Write error:", err)
		return
	}
	defer f.Close()
	f.WriteString(data + "\n")
}
