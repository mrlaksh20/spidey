#!/bin/bash

# Get the target URL from the argument passed by run.sh
TARGET_URL=$1

# Check if domain was provided
if [ -z "$TARGET_URL" ]; then
    echo "❌ Error: No target URL provided."
    exit 1
fi

# Ensure target URL doesn't have protocol to avoid duplicates
CLEAN_TARGET=$(echo "$TARGET_URL" | sed -E 's|https?://||')

# Define output file
OUTPUT_FILE="reports/${CLEAN_TARGET}_active_urls.txt"

# Trap to handle script interruption (SIGINT, SIGTERM)
trap 'echo "[!] Script interrupted. Progress saved in $OUTPUT_FILE"; exit 1' SIGINT SIGTERM

# Run Katana and continuously save URLs
echo "[*] Running Katana... "

katana -u "https://$CLEAN_TARGET" -d 5 -jc | grep -E '\.js$' | tee -a "$OUTPUT_FILE" &
# Wait for katana to finish
wait

# Final message
echo "[*] Finished. Total URLs saved to '$OUTPUT_FILE'"
