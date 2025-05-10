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
                                                                                 *                   [+] Version: v12.20.0
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
