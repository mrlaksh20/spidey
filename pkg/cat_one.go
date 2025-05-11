package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"strconv"
)

// Patterns for categorization
var patterns = map[string]*regexp.Regexp{
	"js.txt":          regexp.MustCompile(`(?i)\.js$`),
	"css.txt":         regexp.MustCompile(`(?i)\.css$`),
	"html.txt":        regexp.MustCompile(`(?i)\.(html|htm|hbs|tmpl|mustache)$`),
	"json.txt":        regexp.MustCompile(`(?i)\.json$`),
	"xml.txt":         regexp.MustCompile(`(?i)\.xml$`),
	"pdf.txt":         regexp.MustCompile(`(?i)\.pdf$`),
	"doc.txt":         regexp.MustCompile(`(?i)\.(doc|docx)$`),
	"xls.txt":         regexp.MustCompile(`(?i)\.(xls|xlsx)$`),
	"ppt.txt":         regexp.MustCompile(`(?i)\.pptx$`),
	"archive.txt":     regexp.MustCompile(`(?i)\.(zip|tar\.gz|tgz|rar|7z)$`),
	"txt.txt":         regexp.MustCompile(`(?i)\.(txt|md|md5)$`),
	"log.txt":         regexp.MustCompile(`(?i)\.log$`),
	"db.txt":          regexp.MustCompile(`(?i)\.(sql|db|sqlite|bak|backup)$`),
	"config.txt":      regexp.MustCompile(`(?i)\.(env|config|conf|ini|yaml|yml)$`),
	"keyfiles.txt":    regexp.MustCompile(`(?i)\.(pem|crt|key|asc|pub|gpg)$`),
	"cache.txt":       regexp.MustCompile(`(?i)\.(cache|cache\.db)$`),
	"scripts.txt":     regexp.MustCompile(`(?i)\.(sh|bat|bin|exe|dll)$`),
	"packages.txt":    regexp.MustCompile(`(?i)\.(tar\.deb|rpm)$`),
	"server.txt":      regexp.MustCompile(`(?i)(status\.html|server-status|ping\.php)$`),
	"gitfiles.txt":    regexp.MustCompile(`(?i)(\.git|\.gitignore|\.gitlab-ci\.yml|\.github/)$`),
	"webfiles.txt":    regexp.MustCompile(`(?i)(sitemap\.xml|robots\.txt)$`),
	"tempfiles.txt":   regexp.MustCompile(`(?i)(\.swp|\.bak|\.old|~)$`),
	"otherfiles.txt":  regexp.MustCompile(`.*`), // Catch-all for unmatched URLs
}

func main() {
	// Get file from CLI if passed
	var selectedFile string
	if len(os.Args) > 1 {
		selectedFile = os.Args[1]
		// Validate file exists
		if _, err := os.Stat(selectedFile); os.IsNotExist(err) {
			fmt.Println("❌ Provided file does not exist:", selectedFile)
			return
		}
		fmt.Println("🧠 [AUTO] File selected via CLI:", selectedFile)
	} else {
		// Manual selection as fallback
		reportDir := "reports"
		reportFiles, err := getReportFiles(reportDir)
		if err != nil {
			fmt.Println("❌ Error reading report directory:", err)
			return
		}

		if len(reportFiles) == 0 {
			fmt.Println("❌ No report files found in", reportDir)
			return
		}

		fmt.Println("\n📂 Available Report Files:")
		for i, file := range reportFiles {
			fmt.Printf("   [%d] %s\n", i+1, file)
		}

		fmt.Print("\n👉 Enter the file number to categorize: ")
		reader := bufio.NewReader(os.Stdin)
		input, err := reader.ReadString('\n')
		if err != nil {
			fmt.Println("❌ Error reading input:", err)
			return
		}

		input = strings.TrimSpace(input)
		if input == "" {
			fmt.Println("❌ No input provided. Exiting.")
			return
		}

		choice, err := strconv.Atoi(input)
		if err != nil || choice < 1 || choice > len(reportFiles) {
			fmt.Println("❌ Invalid choice. Exiting.")
			return
		}

		selectedFile = filepath.Join(reportDir, reportFiles[choice-1])
		fmt.Printf("✅ You selected: %s\n", selectedFile)
	}

	// Extract domain name from filename
	domainName := strings.Split(filepath.Base(selectedFile), "_")[0]

	// Create analytics directory structure
	analyticsDir := filepath.Join("analytics", domainName)
	if err := os.MkdirAll(analyticsDir, 0755); err != nil {
		fmt.Println("❌ Failed to create analytics directory:", err)
		return
	}

	// Read and categorize
	urls, err := readLines(selectedFile)
	if err != nil {
		fmt.Println("❌ Error reading file:", err)
		return
	}

	if err := categorizeURLs(urls, analyticsDir); err != nil {
		fmt.Println("❌ Error categorizing URLs:", err)
		return
	}

	fmt.Println("🎉 URL categorization complete!")
}

func getReportFiles(dir string) ([]string, error) {
	var files []string
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			files = append(files, entry.Name())
		}
	}
	return files, nil
}

func readLines(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines, scanner.Err()
}

func categorizeURLs(urls []string, outputDir string) error {
	categorized := make(map[string][]string)

	for _, url := range urls {
		matched := false

		for filename, pattern := range patterns {
			if pattern.MatchString(url) {
				categorized[filename] = append(categorized[filename], url)
				matched = true
				break
			}
		}

		if !matched {
			categorized["otherfiles.txt"] = append(categorized["otherfiles.txt"], url)
		}
	}

	for filename, urls := range categorized {
		filepath := filepath.Join(outputDir, filename)
		if err := writeToFile(filepath, urls); err != nil {
			fmt.Println("❌ Error writing to", filename, ":", err)
		}
	}

	return nil
}

func writeToFile(filename string, lines []string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for _, line := range lines {
		_, err := writer.WriteString(line + "\n")
		if err != nil {
			return err
		}
	}

	return writer.Flush()
}
