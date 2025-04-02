package main

import (
	"fmt"
	"net/http"
	"os"
	"io"
	"os/signal"
	"syscall"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run urls_filter.go <domain>")
		return
	}
	domain := os.Args[1]
	url := fmt.Sprintf("https://web.archive.org/cdx/search/cdx?url=*.%s/*&collapse=urlkey&output=text&fl=original&filter=original:.*\\.(xls|js|xml|xlsx|json|pdf|sql|doc|docx|pptx|txt|git|zip|tar\\.gz|tgz|bak|7z|rar|log|cache|secret|db|backup|yml|gz|config|csv|yaml|md|md5|exe|dll|bin|ini|bat|sh|tar|deb|rpm|iso|img|env|apk|msi|dmg|tmp|crt|pem|key|pub|asc)$", domain)

	resp, err := http.Get(url)
	if err != nil {
		fmt.Println("Error fetching filtered URLs:", err)
		return
	}
	defer resp.Body.Close()

	// Dynamic filename in the 'reports' folder
	filePath := fmt.Sprintf("reports/%s_filter.txt", domain)
	file, err := os.Create(filePath)
	if err != nil {
		fmt.Println("Error creating file:", err)
		return
	}
	defer file.Close()

	// Handle Ctrl+C and save gathered data before exit
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-interrupt
		fmt.Println("\nInterrupt received, saving progress and exiting...")
		file.Sync()
		os.Exit(0)
	}()

	_, err = io.Copy(file, resp.Body)
	if err != nil {
		fmt.Println("Error writing to file:", err)
		return
	}

	fmt.Printf("✅ Filtered URLs saved to %s\n", filePath)
}
