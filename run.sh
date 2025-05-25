#!/bin/bash

# Define colors
GREEN="\e[32m"
YELLOW="\e[33m"
BLUE="\e[34m"
CYAN="\e[36m"
MAGENTA="\e[35m"
BOLD="\e[1m"
RESET="\e[0m"

# Display banner
#!/bin/bash

# Define red color
echo -e "\e[1;91m
                                                                        *       *                                                                        
                                                                       +         +                                                                       
                                                                   ++++++*******+++++                                                                    
                                                                 +++ ==           += ++++                                                                
                                                              ** ++  =+            +=  ==+++                                                             
                                                            ++  ++  ++             +=+ +=  +++                                                           
                                                          +++   ++ ++               ==  ++   ++*                                                         
                                                         ++    ++ +==               ==+ +=+    +                                                         
                                                        ++    +== +=+++    :  *    +==+  ==    +++                                                       
                                                       ++     +====  ===+ ++  ++ +===  +==+*    ==                                                       
                                                       =+      + ++++=::==========::=+++++      +=+                                                      
                                                      +=+            +=:::::::::::==++           =+                                                      
                                                      +=+             =:::::::::::=              =+                                                      
                                                       =+    ++++**++==:::::::::::=++**+++++*   +=+                                                      
                                                       ++   +=:=    =:==+====::=====    +=:=    ==                                                       
                                                        ++   ==+  *+==+   + ++++  +++++  ==+   +=+                                                       
                                                         ++   ++   =:=    *         =:+  +=   .=+                                                        
                                                          ++   ++  +=+              +=+  ++   ++                                                         
                                                           ++   +   =+              +=  +=  +=+                                                          
                                                             ** ++  ++              ++  ==++++                                                           
                                                               +++   =+            +=  ++++                                                              
                                                                 ++++++            +++++                                                                 
                                                                  +   +++********+++===                                                                  
                                                                   *   +          +                  Developed by [>] "${YELLOW}Laksh ${MAGENTA}[✔]${RESET}"
                                                                                 *                   [+] Version: MARK-43
\e[0m"

# Function to get valid domain input
get_input() {
    local prompt="$1"
    local input_var
    while true; do
        read -e -p "$(echo -e "$prompt")" input_var
        input_var=$(echo "$input_var" | tr -d '[:space:]')

        # Validate input (ensure it's not empty)
        if [[ -n "$input_var" ]]; then
            echo "$input_var"
            return
        else
            echo -e "${RED}[!] Invalid input! Please enter again.${RESET}"
        fi
    done
}

# Function to check active file URL count
check_active_count() {
    local file="$1"
    if [ -f "$file" ]; then
        local count
        count=$(wc -l < "$file")
        echo "$count"
    else
        echo "0"
    fi
}

# Parse mode
if [[ "$1" == "-m" ]]; then
    MODE="manual"
elif [[ "$1" == "-a" ]]; then
    MODE="auto"
else
    echo -e "${RED}[!] Please provide a valid mode: -m (manual) or -a (auto)${RESET}"
    exit 1
fi


# Display menu **before** asking for input
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "${BOLD}${YELLOW} [?] Domain Input ${RESET}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"

# Get valid domain input
domain=$(get_input "${YELLOW}[>]${RESET} Enter the domain (e.g., example.com): ")

echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"

# Check and create 'reports' folder if it doesn't exist
if [ ! -d "reports" ]; then
    mkdir reports
    echo -e "${GREEN}[✔] 'reports' folder created.${RESET}"
fi
echo ""



# ------------------- MANUAL MODE ------------------------
if [[ "$MODE" == "manual" ]]; then
# Run passive recon - Only run All URL test
echo -e "${BLUE}[i]${RESET} Getting Urls from ${CYAN} WEB ARCHIVE ${RESET}..."
go run pkg/urls_all.go "$domain"
echo ""

# Ask if user wants to start active recon
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
active_choice=$(get_input "${YELLOW}[>]${RESET} Do you want to start active recon? (y/n): ")
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo ""

if [[ "$active_choice" =~ ^[Yy]$ ]]; then
    echo -e "${GREEN}🚀 Starting active recon for ${CYAN}$domain${RESET}..."
    bash pkg/active.sh "$domain"
else
    echo -e "${RED}🛑 Skipping active recon.${RESET}"
fi
echo ""

# Categorization prompt
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
categorize_choice=$(get_input "${YELLOW}[>]${RESET} Do you want to categorize the reports? (y/n): ")
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo ""

if [[ "$categorize_choice" =~ ^[Yy]$ ]]; then
    echo -e "${GREEN}📂 Categorizing reports...${RESET}"
    go run pkg/cat_choose.go
else
    echo -e "${RED}🛑 Skipping categorization.${RESET}"
fi
echo ""

echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
probe_req=$(get_input "${YELLOW}[i]${RESET}  wants to Probe categorized Urls? (y/n): ")
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
if [[ "$probe_req" =~ ^[Yy]$ ]]; then
	echo -e "${GREEN}🚀 Executing...${RESET}"
	go run pkg/probe.go
else
	echo -e "${RED}🛑 Probing step inturrepted...Run this command ${cyan}bash pkg/probe.go ${reset}if u interupted accidently... ${RESET}"
fi
echo ""

echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
snapurls_req=$(get_input "${YELLOW}[i]${RESET}  want to retrive every timeline of snapurls? (y/n): ")
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
if [[ "$snapurls_req" =~ ^[Yy]$ ]]; then
        echo -e "${GREEN}🚀 Executing...${RESET}"
	bash pkg/404_choose.sh
else
        echo -e "${RED}[i] process intrupted,run this command ${green} bash pkg/404_choose.sh if u accidently intrupt ${RESET}"
fi
echo ""

go run pkg/scan.go

fi

# ------------------- AUTO MODE --------------------------
if [[ "$MODE" == "auto" ]]; then
    echo -e "${GREEN}[AUTO] 🚀 Starting full auto recon for ${CYAN}$domain${RESET}..."

    # Passive Recon
    echo -e "${BLUE}[AUTO] 🔍 Running urls_all.go...${RESET}"
    go run pkg/urls_all.go "$domain"

    # Active Recon
    echo -e "${BLUE}[AUTO] 🔥 Running active.sh...${RESET}"
    bash pkg/active.sh "$domain"

    # Decide categorization logic
    active_file="reports/${domain}_active_urls.txt"
    all_file="reports/${domain}_all.txt"

    active_count=$(check_active_count "$active_file")
    echo -e "${BLUE}[AUTO] 🧠 Deciding categorization logic... Active URL count = $active_count${RESET}"

    if [[ "$active_count" -gt 0 ]]; then
        echo -e "${GREEN}[AUTO] Running cat_multi.go with active & all URLs...${RESET}"
        go run pkg/cat_multi.go "$all_file" "$active_file"
    else
        echo -e "${YELLOW}[AUTO] No active URLs, running cat_one.go...${RESET}"
        go run pkg/cat_one.go "$all_file"
    fi

    c_folder=""
    d_folder="analytics/${domain}_deduplicates"
    n_folder="analytics/${domain}"

    if [[ -d "$d_folder" ]]; then
        c_folder="$d_folder"
    elif [[ -d "$n_folder" ]]; then
        c_folder="$n_folder"
    else
        echo -e "${RED}[AUTO] there is no otherfiles.txt to refilter${RESET}"
        exit 1
    fi

    grep -Ei '\.js$|\.json$|\.html$' "$c_folder/otherfiles.txt" > "$c_folder/otherfiles_filtered.txt" && mv "$c_folder/otherfiles_filtered.txt" "$c_folder/otherfiles.txt"

	# ------------------ PROBE TIME -------------------
    echo -e "${BLUE}[AUTO] 🧪 Starting probing step...${RESET}"

    probe_folder=""
    dedup_folder="analytics/${domain}_deduplicates"
    normal_folder="analytics/${domain}"

    if [[ -d "$dedup_folder" ]]; then
        probe_folder="$dedup_folder"
    elif [[ -d "$normal_folder" ]]; then
        probe_folder="$normal_folder"
    else
        echo -e "${RED}[AUTO] ❌ No valid analytics folder found to probe.${RESET}"
        exit 1
    fi

    echo -e "${GREEN}[AUTO] 🎯 Probing folder: $probe_folder${RESET}"
    go run pkg/probe.go "$probe_folder" -f js,json,html,config,otherfiles,archive

    # ------------------ 404 SCANNING TIME -------------------
    echo -e "${BLUE}[AUTO] 🕳️ Starting 404 scanner...${RESET}"

    # Extract basename to get the folder name (e.g., domain or domain_deduplicates)
    probe_basename=$(basename "$probe_folder")

    probe_output_folder="probe/$probe_basename"

    if [[ -d "$probe_output_folder" ]]; then
        echo -e "${GREEN}[AUTO] 📁 Running 404 scanner on $probe_output_folder${RESET}"
        go run pkg/404_1.go "$probe_output_folder" -f config404,config200,archive404,archive200,js404,json404,html404,js200,json200,html200,otherfiles200,otherfiles404,jsotherres,jsonotherres,configotherres,htmlotherres,otherfilesotherres
    else
        echo -e "${RED}[AUTO] ❌ Probe output folder not found: $probe_output_folder${RESET}"
        exit 1
    fi
    # ------------------ LEAK SCANNING TIME -------------------

    echo -e "${BLUE}[AUTO] 🕵️ Starting scan.go leak detection...${RESET}"

    SCAN_ORDER=("config404" "config200" "js404" "json404" "html404" "otherfiles404" "js200" "json200" "html200" "otherfiles200" "configotherres" "jsonotherres" "jsotherres" "htmlotherres" "otherfilesotherres" )

    for category in "${SCAN_ORDER[@]}"; do
        scan_file="${probe_basename}_${category}_scan.txt"
        full_path="snapurls/$scan_file"

        if [[ -f "$full_path" ]]; then
            echo -e "${GREEN}[AUTO] 🔬 Scanning: $scan_file${RESET}"
            go run pkg/scan.go -f "$scan_file"
        else
            echo -e "${YELLOW}[AUTO] ⚠️ File not found, skipping: $scan_file${RESET}"
        fi
    done
fi

