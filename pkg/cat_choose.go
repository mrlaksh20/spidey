package main

import (
	"fmt"
	"os"
	"os/exec"
)

// Fancy banner just for vibes
func showBanner() {
	fmt.Println("=======================================")
	fmt.Println("🚀 Welcome to the Report Categorizer 🚀")
	fmt.Println("=======================================")
}

// Ask user whether to categorize one or multiple files
func chooseCategorization() {
	fmt.Println("\n📝 How would you like to categorize the reports?")
	fmt.Println("   [1] Categorize ONE file(like allurls file)")
	fmt.Println("   [2] Categorize MULTIPLE files(like active + Passive source)")

	var choice int
	fmt.Print("👉 Enter your choice (1/2): ")
	_, err := fmt.Scan(&choice)
	if err != nil {
		fmt.Println("❌ Invalid input. Please enter 1 or 2.")
		return
	}

	switch choice {
	case 1:
		fmt.Println("✅ You chose to categorize ONE file.")
		runScript("pkg/cat_one.go")
	case 2:
		fmt.Println("✅ You chose to categorize MULTIPLE files.")
		runScript("pkg/cat_multi.go")
	default:
		fmt.Println("⚠️ Invalid choice. Please select 1 or 2.")
	}
}

// Helper function to run a Go script
func runScript(script string) {
	cmd := exec.Command("go", "run", script)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		fmt.Println("❌ Error running script:", err)
	}
}

func main() {
	showBanner()
	chooseCategorization()
}
