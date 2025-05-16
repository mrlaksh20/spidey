// MODIFIED: 404_2.go
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"sort"
)

// Web Archive API URL format
const archiveAPI = "https://web.archive.org/__wb/calendarcaptures/2?url=%s&date=%d&groupby=day"

// Headers for the request
var headers = map[string]string{
	"Host":             "web.archive.org",
	"User-Agent":       "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
	"Accept":           "*/*",
	"Accept-Language":  "en-US,en;q=0.5",
	"Accept-Encoding":  "gzip, deflate, br",
	"Referer":          "https://web.archive.org/web/",
	"Sec-Fetch-Dest":   "empty",
	"Sec-Fetch-Mode":   "cors",
	"Sec-Fetch-Site":   "same-origin",
	"Priority":         "u=4",
	"Te":               "trailers",
	"Cookie":           "donation-identifier=; donation=x; view-search=tiles; showdetails-search=; abtest-identifier=",
}

type ArchiveResponse struct {
	Items []interface{} `json:"items"`
}

var (
	yearFile       string
	targetFolder   string
	targetFileName string
	wg             sync.WaitGroup
	semaphore      = make(chan struct{}, 5)
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run 404_2.go <yearFile> , file format must be example.com_js_yr.txt")
		return
	}

	yearFile = os.Args[1]

	file, err := os.Open(yearFile)
	if err != nil {
		fmt.Printf("❌ Error opening file: %v\n", err)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		wg.Add(1)
		go processLine(line)
	}

	wg.Wait()

	if err := scanner.Err(); err != nil {
		fmt.Printf("❌ Error reading file: %v\n", err)
	}

	trigger404_3(targetFolder, targetFileName)
}

func processLine(line string) {
	defer wg.Done()

	re := regexp.MustCompile(`^(https?://[^\s]+):\[(.+)\]$`)
	matches := re.FindStringSubmatch(line)
	if len(matches) != 3 {
		fmt.Printf("⚠️ Skipping malformed line: %s\n", line)
		return
	}

	url := matches[1]
	years := strings.Split(matches[2], ",")

	for _, year := range years {
		year = strings.TrimSpace(year)
		yearInt := parseYear(year)
		if yearInt == 0 {
			fmt.Printf("⚠️ Invalid year: %s\n", year)
			continue
		}

		semaphore <- struct{}{}
		wg.Add(1)
		go fetchArchiveData(url, yearInt)
	}
}

func parseYear(year string) int {
	yearInt, err := strconv.Atoi(year)
	if err != nil {
		return 0
	}
	return yearInt
}

func fetchArchiveData(url string, year int) {
	defer wg.Done()
	defer func() { <-semaphore }()

	apiURL := fmt.Sprintf(archiveAPI, url, year)

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		fmt.Printf("❌ Error creating request: %v\n", err)
		return
	}

	for key, value := range headers {
		req.Header.Set(key, value)
	}

	client := &http.Client{Timeout: 20 * time.Second}
	maxRetries := 5
	var resp *http.Response

	for attempt := 1; attempt <= maxRetries; attempt++ {
		resp, err = client.Do(req)
		if err == nil {
			break
		}
		fmt.Printf("❌ Attempt %d/%d: Error making request: %v\n", attempt, maxRetries, err)
		time.Sleep(time.Duration(attempt) * 3 * time.Second)
	}

	if err != nil {
		fmt.Printf("❌ Failed after %d retries: %v\n", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		fmt.Printf("⚠️ Skipping URL: %s (HTTP %d)\n", url, resp.StatusCode)
		return
	}

	var archiveResponse ArchiveResponse
	if err := json.NewDecoder(resp.Body).Decode(&archiveResponse); err != nil {
		fmt.Printf("❌ Error decoding JSON: %v\n", err)
		return
	}

	processArchiveData(url, year, archiveResponse.Items)
}

func processArchiveData(url string, year int, items []interface{}) {
	var allValidDates []string

	for _, item := range items {
		switch v := item.(type) {
		case []interface{}:
			if len(v) < 3 {
				continue
			}

			mmdd, ok1 := toInt(v[0])
			statusCode, ok2 := toInt(v[1])
			snapshots, ok3 := toInt(v[2])

			if !ok2 {
				statusCode = 200
			}

			if !ok1 || !ok3 {
				continue
			}

			if statusCode == 200 || (statusCode == 301 && snapshots > 1) || v[1] == "-" {
				fullDate := fmt.Sprintf("%d%s", year, formatMMDD(mmdd))
				allValidDates = append(allValidDates, fullDate)
			}
		default:
			fmt.Printf("⚠️ Unexpected item format: %v\n", v)
		}
	}

	// 🧠 LIMIT: Only pick first 3 dates MAX per year
	sort.Strings(allValidDates)
	limitedDates := allValidDates
	if len(allValidDates) > 3 {
		limitedDates = allValidDates[:2]
	}

	if len(limitedDates) > 0 {
		saveResults(url, limitedDates)
	}
}

func toInt(value interface{}) (int, bool) {
	switch v := value.(type) {
	case float64:
		return int(v), true
	case int:
		return v, true
	case string:
		if num, err := strconv.Atoi(v); err == nil {
			return num, true
		}
	}
	return 0, false
}

func formatMMDD(mmdd int) string {
	return fmt.Sprintf("%04d", mmdd)
}

func saveResults(url string, dates []string) {
	result := fmt.Sprintf("%s:{[%s]}\n", url, strings.Join(dates, ","))
	// 👇 SHOW the result exactly how it's saved
	fmt.Printf("📦 [dd/mm/yyyy] Archived Snapday: %s", result)
	yearFileBase := filepath.Base(yearFile)
	yearFileDir := filepath.Dir(yearFile)

	pathParts := strings.Split(yearFileBase, "_")
	if len(pathParts) < 2 {
		fmt.Printf("❌ Error: Invalid file format: %s\n", yearFileBase)
		return
	}

	targetFolder = filepath.Base(yearFileDir)
	targetFileName = strings.TrimSuffix(yearFileBase, "_yr.txt")

	outputPath := fmt.Sprintf("404_analysis/%s/%s_ts.txt", targetFolder, targetFileName)

	file, err := os.OpenFile(outputPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("❌ Error opening output file: %v\n", err)
		return
	}
	defer file.Close()

	if _, err := file.WriteString(result); err != nil {
		fmt.Printf("❌ Error writing to output file: %v\n", err)
	}
}

func trigger404_3(targetFolder, targetFileName string) {
	tsFile := fmt.Sprintf("404_analysis/%s/%s_ts.txt", targetFolder, targetFileName)
	fmt.Printf("💀 [404_3.go] Extracting HHMMSS from snapdays %s\n", tsFile)

	cmd := exec.Command("go", "run", "pkg/404_3.go", tsFile)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		fmt.Printf("❌ Error running 404_3.go: %v\n", err)
	}
}
