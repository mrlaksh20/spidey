package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Patterns for categorization
var patterns = map[string]*regexp.Regexp{
	"js.txt":         regexp.MustCompile(`(?i)\.js(\?.*)?$`),
	"css.txt":        regexp.MustCompile(`(?i)\.css(\?.*)?$`),
	"html.txt":       regexp.MustCompile(`(?i)\.(html|htm|hbs|tmpl|mustache)(\?.*)?$`),
	"json.txt":       regexp.MustCompile(`(?i)\.json(\?.*)?$`),
	"xml.txt":        regexp.MustCompile(`(?i)\.xml(\?.*)?$`),
	"pdf.txt":        regexp.MustCompile(`(?i)\.pdf(\?.*)?$`),
	"doc.txt":        regexp.MustCompile(`(?i)\.(doc|docx)(\?.*)?$`),
	"xls.txt":        regexp.MustCompile(`(?i)\.(xls|xlsx)(\?.*)?$`),
	"ppt.txt":        regexp.MustCompile(`(?i)\.pptx(\?.*)?$`),
	"archive.txt":    regexp.MustCompile(`(?i)\.(zip|tar\.gz|tgz|rar|7z)(\?.*)?$`),
	"txt.txt":        regexp.MustCompile(`(?i)\.(txt|md|md5)(\?.*)?$`),
	"log.txt":        regexp.MustCompile(`(?i)\.log(\?.*)?$`),
	"db.txt":         regexp.MustCompile(`(?i)\.(sql|db|sqlite|bak|backup)(\?.*)?$`),
	"config.txt":     regexp.MustCompile(`(?i)\.(env|config|conf|ini|yaml|yml)(\?.*)?$`),
	"keyfiles.txt":   regexp.MustCompile(`(?i)\.(pem|crt|key|asc|pub|gpg)(\?.*)?$`),
	"cache.txt":      regexp.MustCompile(`(?i)\.(cache|cache\.db)(\?.*)?$`),
	"scripts.txt":    regexp.MustCompile(`(?i)\.(sh|bat|bin|exe|dll)(\?.*)?$`),
	"packages.txt":   regexp.MustCompile(`(?i)\b(tar\.deb|rpm)\b`),
	"server.txt":     regexp.MustCompile(`(?i)\b(status\.html|server-status|ping\.php)\b`),
	"gitfiles.txt":   regexp.MustCompile(`(?i)(\.git|\.gitignore|\.gitlab-ci\.yml|\.github/)(\?.*)?$`),
	"webfiles.txt":   regexp.MustCompile(`(?i)\b(sitemap\.xml|robots\.txt)\b`),
	"tempfiles.txt":  regexp.MustCompile(`(?i)\b(\.swp|\.bak|\.old|~)\b`),
	"otherfiles.txt":  regexp.MustCompile(`.*`), // Catch-all for unmatched URLs
}

func main() {
	// Check for auto-mode args
	if len(os.Args) == 3 {
		allFile := os.Args[1]
		activeFile := os.Args[2]

		fmt.Println("🤖 Auto-mode activated!")
		fmt.Println("📁 All File   :", allFile)
		fmt.Println("📁 Active File:", activeFile)

		files := []string{
			filepath.Base(allFile),
			filepath.Base(activeFile),
		}

		// Place files inside "reports" directory for consistency
		for _, f := range files {
			if _, err := os.Stat(filepath.Join("reports", f)); os.IsNotExist(err) {
				fmt.Println("❌ File not found in reports/:", f)
				return
			}
		}

		domain := extractBaseNames(files)[0]
		targetDir := createAnalyticsFolder(domain, files)
		mergedURLs := deduplicateFiles(files)
		processFiles(mergedURLs, targetDir)
		return
	}

	// Manual mode
	fmt.Println("\n---------- Multi-files Categorization ----------")
	fmt.Println("Choose an option:")
	fmt.Println("[1] Analyze multiple files")
	fmt.Println("[2] Deduplicate multiple files and analyze")
	fmt.Println("----------------------------------------------------")
	fmt.Print("👉 Enter your choice (1/2): ")

	var choice string
	fmt.Scan(&choice)

	switch choice {
	case "1":
		analyzeMultipleFiles()
	case "2":
		deduplicateAndAnalyze()
	default:
		fmt.Println("❌ Invalid choice! Please select either 1 or 2.")
	}
}

func analyzeMultipleFiles() {
	selectedFiles := getFileSelections()
	if len(selectedFiles) == 0 {
		return
	}

	domain := extractBaseNames(selectedFiles)[0]
	targetDir := createAnalyticsFolder(domain, selectedFiles)
	processFiles(selectedFiles, targetDir)
}

func deduplicateAndAnalyze() {
	selectedFiles := getFileSelections()
	if len(selectedFiles) < 2 {
		fmt.Println("❌ At least two files are required for deduplication.")
		return
	}

	domain := extractBaseNames(selectedFiles)[0]
	dedupDir := createUniqueDedupFolder(domain)
	deduplicatedURLs := deduplicateFiles(selectedFiles)
	processFiles(deduplicatedURLs, dedupDir)
}

func getFileSelections() []string {
	reportDir := "reports"
	files, err := os.ReadDir(reportDir)
	if err != nil {
		fmt.Println("❌ Error reading reports directory:", err)
		return nil
	}

	fmt.Println("\n📂 Available Report Files:")
	for i, file := range files {
		fmt.Printf("   [%d] %s\n", i+1, file.Name())
	}

	fmt.Print("\nEnter the file numbers you want to analyze (comma-separated, e.g., 1,2,4): ")
	var input string
	fmt.Scan(&input)

	selections := strings.Split(input, ",")
	var selectedFiles []string
	var indices []int

	for _, sel := range selections {
		index := strings.TrimSpace(sel)
		num, err := strconv.Atoi(index)
		if err != nil || num < 1 || num > len(files) {
			fmt.Println("❌ Invalid file selection:", index)
			return nil
		}
		indices = append(indices, num-1)
	}

	sort.Ints(indices) // Sorting the file indices

	for _, i := range indices {
		selectedFiles = append(selectedFiles, files[i].Name())
	}

	fmt.Println("✅ Selected files:", selectedFiles)
	return selectedFiles
}

func createAnalyticsFolder(domain string, selectedFiles []string) string {
	analyticsDir := "analytics"
	targetDir := filepath.Join(analyticsDir, domain+"_deduplicates")

	if err := os.MkdirAll(targetDir, 0755); err != nil {
		fmt.Println("❌ Failed to create analytics folder:", err)
		return ""
	}

	return targetDir
}

func createUniqueDedupFolder(domain string) string {
	analyticsDir := "analytics"
	baseFolder := filepath.Join(analyticsDir, domain+"_deduplicates")
	counter := 1

	uniqueFolder := baseFolder
	for {
		if _, err := os.Stat(uniqueFolder); os.IsNotExist(err) {
			break
		}
		counter++
		uniqueFolder = fmt.Sprintf("%s_%d", baseFolder, counter)
	}

	if err := os.MkdirAll(uniqueFolder, 0755); err != nil {
		fmt.Println("❌ Failed to create unique deduplication folder:", err)
		return ""
	}

	return uniqueFolder
}

func deduplicateFiles(files []string) []string {
	urlSet := make(map[string]struct{})

	for _, file := range files {
		filePath := filepath.Join("reports", file)
		file, err := os.Open(filePath)
		if err != nil {
			fmt.Println("❌ Error reading file:", file)
			continue
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				urlSet[line] = struct{}{}
			}
		}

		if err := scanner.Err(); err != nil {
			fmt.Println("❌ Error reading from file:", file)
		}
	}

	var uniqueURLs []string
	for url := range urlSet {
		uniqueURLs = append(uniqueURLs, url)
	}

	sort.Strings(uniqueURLs) // Sorting deduplicated URLs for consistency
	return uniqueURLs
}

func processFiles(urls []string, targetDir string) {
	for _, url := range urls {
		matched := false

		for filename, pattern := range patterns {
			if pattern.MatchString(url) {
				if err := appendToFile(filepath.Join(targetDir, filename), url); err != nil {
					fmt.Println("❌ Error appending to", filename, ":", err)
				}
				matched = true
				break
			}
		}

		if !matched {
			if err := appendToFile(filepath.Join(targetDir, "otherfiles.txt"), url); err != nil {
				fmt.Println("❌ Error appending to otherfiles.txt:", err)
			}
		}
	}

	fmt.Println("🎉 Categorization complete! Results saved in:", targetDir)
}

func extractBaseNames(files []string) []string {
	var names []string
	for _, file := range files {
		name := strings.Split(file, "_")[0]
		names = append(names, name)
	}
	return names
}

func appendToFile(filename, line string) error {
	file, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.WriteString(line + "\n")
	return err
}
