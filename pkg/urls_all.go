package main

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
)

func fetchAllURLs(domain string) {
	url := fmt.Sprintf("https://web.archive.org/cdx/search/cdx?url=*.%s/*&collapse=urlkey&output=text&fl=original", domain)

	resp, err := http.Get(url)
	if err != nil {
		fmt.Println("Error fetching URLs:", err)
		return
	}
	defer resp.Body.Close()

	// Save directly into the 'reports' folder — one level up from 'pkg'
	filePath := fmt.Sprintf("reports/%s_all.txt", domain)
	file, err := os.Create(filePath)
	if err != nil {
		fmt.Println("Error creating file:", err)
		return
	}
	defer file.Close()


	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\nInterrupt received, saving progress...")
		file.Sync()
		os.Exit(0)
	}()

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		fmt.Println(line)
		file.WriteString(line + "\n")
	}

	if err := scanner.Err(); err != nil {
		fmt.Println("Error reading response:", err)
	}
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: urls_all <domain>")
		os.Exit(1)
	}
	domain := os.Args[1]
	fetchAllURLs(domain)
}
