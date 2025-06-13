package main  
  
import (  
        "bufio"  
        "fmt"  
        "net/http"  
        "os"  
        "os/signal"  
        "strings"  
        "syscall"  
        "time"  
)  
  
func fetchAllURLs(domain string) {  
        url := fmt.Sprintf("https://web.archive.org/cdx/search/cdx?url=*.%s/*&collapse=urlkey&output=text&fl=original", domain)  
  
        resp, err := http.Get(url)  
        if err != nil {  
                fmt.Println("Error fetching URLs:", err)  
                return  
        }  
        defer resp.Body.Close()  
  
        // Ensure reports folder exists  
        os.MkdirAll("reports", os.ModePerm)  
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
  
        // Spinner + live count  
	spinnerChars := []rune{'-', '\\', '|', '/'}
        count := 0  
        spinnerIndex := 0  
  
        // Spinner loop (in background)  
        done := make(chan bool)  
        go func() {  
                for {  
                        select {  
                        case <-done:  
                                return  
                        default:  
                                fmt.Printf("\r[%c] Fetched: %d URLs", spinnerChars[spinnerIndex], count)  
                                spinnerIndex = (spinnerIndex + 1) % len(spinnerChars)  
                                time.Sleep(100 * time.Millisecond)  
                        }  
                }  
        }()  
  
        // Reading lines  
        scanner := bufio.NewScanner(resp.Body)  
        for scanner.Scan() {  
                line := strings.TrimSpace(scanner.Text())  
                if line == "" {  
                        continue  
                }  
                count++  
                file.WriteString(line + "\n")  
        }  
  
        done <- true // stop spinner  
  
        if err := scanner.Err(); err != nil {  
                fmt.Println("\nError reading response:", err)  
        } else {  
                fmt.Printf("\r[✓] Completed! Total: %d URLs\n", count)  
        }  
}
func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run test.go <domain>")
		os.Exit(1)
	}
	domain := os.Args[1]
	fetchAllURLs(domain)
}
