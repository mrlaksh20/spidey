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
                                                                   *   +          +                 🕸️   Developed by:"${YELLOW} Parthiban, Rageswaran, Laksh${RESET}"
                                                                                 *                  [+] Version: v12.20.0
\e[0m"

get_choice() {
    local prompt="$1"
    local input_var
    while true; do
        read -e -p "$(echo -e "$prompt")" input_var
        input_var=$(echo "$input_var" | tr -d '[:space:]')

        # Validate input (must be 1, 2, or 3)
        if [[ "$input_var" =~ ^[123]$ ]]; then
            echo "$input_var"
            return
        else
            echo -e "${RED}[!] Invalid choice! Please enter 1, 2, or 3.${RESET}"
        fi
    done
}

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

# Display menu **before** asking for input
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "${BOLD}${YELLOW} [?] Choose an option: ${RESET}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "  ${CYAN}1️⃣  Gather All Urls ${RESET}"
echo -e "  ${CYAN}2️⃣  Get Filter Urls ${RESET}"
echo -e "  ${CYAN}3️⃣  Both (1 & 2) ${RESET}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"

# Get valid choice input **AFTER** showing the menu
choice=$(get_choice "${YELLOW}[>]${RESET} Enter your choice (1/2/3): ")

echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"

# Get valid domain input
domain=$(get_input "${YELLOW}[>]${RESET} Enter the domain (e.g., example.com): ")

echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo ""

# Check and create 'reports' folder if it doesn't exist
if [ ! -d "reports" ]; then
    mkdir reports
    echo -e "${GREEN}[✔] 'reports' folder created.${RESET}"
fi
echo ""

# Run passive recon based on choice
case $choice in
  1)
    echo -e "${BLUE}[i]${RESET} Running ${CYAN}All URL test${RESET}..."
    go run pkg/urls_all.go "$domain"
    ;;
  2)
    echo -e "${BLUE}[i]${RESET} Running ${CYAN}Filter URL test${RESET}..."
    go run pkg/urls_filter.go "$domain"
    ;;
  3)
    echo -e "${BLUE}[i]${RESET} Running ${CYAN}All URL test${RESET}..."
    go run pkg/urls_all.go "$domain"
    echo -e "${BLUE}[i]${RESET} Running ${CYAN}Filter URL test${RESET}..."
    go run pkg/urls_filter.go "$domain"
    ;;
esac
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
echo -e "${YELLOW}[i]${RESET}To Probe request,use: ${GREEN}go run pkg/probe.go${RESET}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
