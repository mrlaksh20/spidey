package main

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Probe folder path
const probeFolder = "probe"

var stopCurrent bool // Only stops the current file's probing, not the whole process

var fastClient = &http.Client{
	Timeout: 10 * time.Second,
	Transport: &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		MaxConnsPerHost:     100,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  false,
	},
}

func main() {
	var targetFolder string
	var fileTypes string

	// Custom flag-style logic (basic and flexible)
	args := os.Args[1:]
	if len(args) == 0 {
		fmt.Println("Usage: go run pkg/probe.go <target-folder> [-f all|html,js,json]")
		fmt.Println("       Or run without args to enter manual mode.")
		runManualMode()
		return
	}

	targetFolder = args[0]

	if len(args) > 2 && args[1] == "-f" {
		fileTypes = args[2]
	} else {
		fmt.Println("❌ Invalid flags. Usage: go run pkg/probe.go <target-folder> -f all|html,js,json")
		return
	}

	targetProbePath := filepath.Join(probeFolder, filepath.Base(targetFolder))
	if err := os.MkdirAll(targetProbePath, os.ModePerm); err != nil {
		fmt.Println("❌ Error creating probe folder:", err)
		return
	}

	files, err := os.ReadDir(targetFolder)
	if err != nil {
		fmt.Println("❌ Error reading target folder:", err)
		return
	}

	var fileList []string
	if fileTypes == "all" {
		for _, file := range files {
			if !file.IsDir() && strings.HasSuffix(file.Name(), ".txt") {
				fileList = append(fileList, file.Name())
			}
		}
	} else {
		types := strings.Split(fileTypes, ",")
		for _, ext := range types {
			name := ext + ".txt"
			for _, file := range files {
				if file.Name() == name {
					fileList = append(fileList, name)
				}
			}
		}
	}

	if len(fileList) == 0 {
		fmt.Println("❌ No matching files to probe.")
		return
	}

	fmt.Printf("\n🎯 Probing target: %s %s\n", targetFolder, fileList)

	// Handle Ctrl+C
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		for range sigChan {
			stopCurrent = true
			fmt.Print("\r")
		}
	}()

	for _, file := range fileList {
		stopCurrent = false
		fmt.Printf("\n🔍 Probing file: %s\n", file)
		filePath := filepath.Join(targetFolder, file)
		probeFile(filePath, targetProbePath, file)
		if !stopCurrent {
			fmt.Printf("✅ Probing completed: %s\n", file)
		}
	}
	fmt.Printf("\n📁 Probe output saved in: %s\n", targetProbePath)
	fmt.Println(targetProbePath) // 👈 THIS one is important — this is what run.sh will capture!
}

func runManualMode() {
	analyticsPath := "analytics"

	if _, err := os.Stat(analyticsPath); os.IsNotExist(err) {
		fmt.Println("❌ Analytics folder not found!")
		return
	}

	domainFolders, err := os.ReadDir(analyticsPath)
	if err != nil {
		fmt.Println("❌ Error reading analytics folder:", err)
		return
	}

	if len(domainFolders) == 0 {
		fmt.Println("❌ No target folders found in analytics!")
		return
	}

	fmt.Println("\n📂 Available Targets:")
	for i, folder := range domainFolders {
		if folder.IsDir() {
			fmt.Printf("   [%d] %s\n", i+1, folder.Name())
		}
	}

	fmt.Print("\n🎯 Choose target by number: ")
	var choice int
	fmt.Scan(&choice)

	if choice < 1 || choice > len(domainFolders) {
		fmt.Println("❌ Invalid choice!")
		return
	}

	target := domainFolders[choice-1].Name()
	fmt.Printf("\n🚀 Target selected: %s\n", target)

	targetProbePath := filepath.Join(probeFolder, target)
	if err := os.MkdirAll(targetProbePath, os.ModePerm); err != nil {
		fmt.Println("❌ Error creating target probe folder:", err)
		return
	}

	targetPath := filepath.Join(analyticsPath, target)
	files, err := os.ReadDir(targetPath)
	if err != nil {
		fmt.Println("❌ Error reading target folder:", err)
		return
	}

	var fileList []string
	fmt.Println("\n📝 Files to probe:")
	for _, file := range files {
		if !file.IsDir() && strings.HasSuffix(file.Name(), ".txt") {
			fileList = append(fileList, file.Name())
			fmt.Printf("   - %s\n", file.Name())
		}
	}

	if len(fileList) == 0 {
		fmt.Println("❌ No files found to probe!")
		return
	}

	// Handle Ctrl+C
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		for range sigChan {
			stopCurrent = true
			fmt.Print("\r")
		}
	}()

	for _, file := range fileList {
		stopCurrent = false
		fmt.Printf("\n🔍 Probing file: %s\n", file)
		filePath := filepath.Join(targetPath, file)
		probeFile(filePath, targetProbePath, file)
		if !stopCurrent {
			fmt.Printf("✅ Probing completed: %s\n", file)
		}
	}
}
func probeFile(filePath, targetProbePath, fileName string) {
	file, err := os.Open(filePath)
	if err != nil {
		fmt.Printf("❌ Error opening file %s: %v\n", filePath, err)
		return
	}
	defer file.Close()

	// Count total URLs first
	var urls []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		url := strings.TrimSpace(scanner.Text())
		if url != "" {
			urls = append(urls, url)
		}
	}
	total := len(urls)
	if total == 0 {
		fmt.Printf("⚠️  No URLs found in %s\n", fileName)
		return
	}

	// Reset file pointer
	file.Seek(0, 0)

	const MaxWorkers = 30
	var wg sync.WaitGroup
	urlCh := make(chan string, 100)

	var completed int
	var mu sync.Mutex

	start := time.Now()

	// Progress Bar ticker
	ticker := time.NewTicker(300 * time.Millisecond)
	go func() {
		for range ticker.C {
			mu.Lock()
			percent := float64(completed) / float64(total) * 100
			barWidth := 20
			doneBars := int(percent / (100 / float64(barWidth)))
			bar := strings.Repeat("█", doneBars) + strings.Repeat("░", barWidth-doneBars)

			elapsed := time.Since(start)
			rate := float64(completed) / elapsed.Seconds()
			remaining := time.Duration(float64(total-completed)/rate) * time.Second

			status := fmt.Sprintf("\r🔍 %s [%d/%d] [%s] %4.1f%% ETA: %s", fileName, completed, total, bar, percent, remaining.Truncate(time.Second))

			fmt.Print(status)
			mu.Unlock()
		}
	}()

	for i := 0; i < MaxWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for url := range urlCh {
				if stopCurrent {
					return
				}
				if err := probeURL(url, targetProbePath, fileName); err != nil {
					logFailedURL(targetProbePath, url, err)
				}
				mu.Lock()
				completed++
				mu.Unlock()
			}
		}()
	}

	for _, url := range urls {
		if stopCurrent {
			break
		}
		urlCh <- url
	}

	close(urlCh)
	wg.Wait()
	ticker.Stop()

	// Final flush
	percent := float64(completed) / float64(total) * 100
	bar := strings.Repeat("█", 20)
	finalLine := fmt.Sprintf("\r🔍 %s [%d/%d] [%s] %4.1f%% ETA: 0s\n", fileName, completed, total, bar, percent)
	fmt.Print(finalLine)
}

func probeURL(url, targetProbePath, fileName string) error {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return fmt.Errorf("request creation failed: %v", err)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (SpideyScan/1.0)")

	resp, err := fastClient.Do(req)
	if err != nil {
		return fmt.Errorf("HTTP request failed: %v", err)
	}
	defer resp.Body.Close()

	var statusSuffix string
	switch resp.StatusCode {
	case 200:
		statusSuffix = "200"
	case 403:
		statusSuffix = "403"
	case 404:
		statusSuffix = "404"
	default:
		statusSuffix = "otherres"
	}

	baseName := strings.TrimSuffix(fileName, ".txt")
	newFileName := fmt.Sprintf("%s%s.txt", baseName, statusSuffix)
	savePath := filepath.Join(targetProbePath, newFileName)

	if err := saveURL(savePath, url); err != nil {
		return fmt.Errorf("failed to save URL: %v", err)
	}
	return nil
}

func logFailedURL(targetProbePath, url string, err error) {
	failedPath := filepath.Join(targetProbePath, "failed_urls.txt")
	file, ferr := os.OpenFile(failedPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if ferr != nil {
		fmt.Printf("❌ Failed to log URL %s: %v\n", url, ferr)
		return
	}
	defer file.Close()

	logEntry := fmt.Sprintf("%s\n", url)
	file.WriteString(logEntry)
}

func saveURL(filePath, url string) error {
	file, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("error opening file %s: %v", filePath, err)
	}
	defer file.Close()

	if _, err := file.WriteString(url + "\n"); err != nil {
		return fmt.Errorf("error writing URL to file %s: %v", filePath, err)
	}
	return nil
}
