#!/bin/bash

# ░▒▓███ 404 Selection Interface - TVA Tempad Style ███▓▒░
# Function to display a live clock in 24-hour format
echo -e "\e[38;5;214m
					                                     ...........                         
					                                -#+------------+####.                    
	 				                            .#----------##---------####-                 
 			       	                                  -+----------------------#---###+               
					  +-. .+                .+-----------------------------+###+             
					  ++--#-+.             +---------------------------------####.           
					   +----##            #------++###+-----------------------####-          
					    .----#.          #-#--+-#-------#----#-#-----#+--------####.         
					       .#-#         #------+--####---#---#--###----#-----#--####.        
					         ###       -+------+-+###+---#-+---####-----+-------####+        
					          ###      #---------######--+-----###------#--------####        
					           ###+    #---------######--#-+--+#####----+--------####.       
					            +####-.#--+------######--+----+#####---+---------####.                       
					              .#####---------######-#-+---+#####-------------####.       
					                  +#------------------#+-----+++---------++--####.       
					                   -+------------+-#------------------------+#####+      
					                    #------------#--------------------------#########    
					                    .#-+-------------------++--------------####. .#####  
					                     .#---------------###+----------------############+  
	                                                      .#-------------------------------#-####-+-.        
					                        ++-----------------------------+###-----         
					                          #--#+-----------------------###.  --+.         
					                            +#--------#--------+---####.    ---+-+.      
					                               .#+----+---------###-           ..        
					                                   +#.----+##.                           
					                                   -#      .#.                           
					                                   .#       -#                           
					                                    #-       #-                          
					                                    .#+      ##                          
					                                     .###. .+##+                         
					                                     .---+..+---+                        
					                                   .#-----+.+----+.                      
					                                  #----+-   .#++++#                      
                                              
                                                                Time: $(date +"%-H:%M:%S %d-%m-%Y (%A)")          
\e[0m" # Reset color
PROBE_DIR="probe/"
list_folders() {
    local dir="$1"
    local folders=("$dir"*/)

    if [ ${#folders[@]} -eq 0 ]; then
        echo -e "\n\033[1;31m[✘] No available targets in $dir\033[0m"
        exit 1
    fi
    echo -e "\n📂 \033[1;36mAvailable Target Folders:\033[0m"
    for i in "${!folders[@]}"; do
        folder_name=$(basename "${folders[i]}")
        echo -e "   [\033[1;33m$((i+1))\033[0m] \033[1;37m$folder_name/\033[0m"
    done
}

# Function to list available files
list_files() {
    local dir="$1"
    local files=("$dir"/*)
    
    if [ ${#files[@]} -eq 0 ]; then
        echo -e "\n\033[1;31m[✘] No response files found in $dir/\033[0m"
        exit 1
    fi

    echo -e "\n📜 \033[1;36mAvailable Files in '$dir/'\033[0m"
    for i in "${!files[@]}"; do
        file_name=$(basename "${files[i]}")
        echo -e "   [\033[1;33m$((i+1))\033[0m] \033[1;37m$file_name\033[0m"
    done
}

# Function to get valid numeric input with arrow key handling
get_valid_number() {
    local prompt="$1"
    local input
    while true; do
        # Use `read -e` to enable proper arrow key movement
        read -e -rp "$prompt" input

        # Allow empty input (ENTER to retry)
        if [[ -z "$input" ]]; then
            continue
        fi
        # Ensure input is a valid number
        if [[ "$input" =~ ^[0-9]+$ ]]; then
            echo "$input"
            return
        else
            echo -e "\033[1;31m[✘] Invalid input! Enter a valid number.\033[0m"
        fi
    done
}

# Step 1: Select target folder
list_folders "$PROBE_DIR"
target_choice=$(get_valid_number $'\n🔹 Select a target folder (number): ')

target_folder=$(ls -d "$PROBE_DIR"*/ | sed -n "${target_choice}p")
if [ -z "$target_folder" ]; then
    echo -e "\n\033[1;31m[✘] Invalid selection. Exiting...\033[0m"
    exit 1
fi

target_folder_name=$(basename "$target_folder")
echo -e "\n✅ Target Folder Selected: \033[1;32m$target_folder_name/\033[0m"

# Step 2: Select target file
list_files "$target_folder"
file_choice=$(get_valid_number $'\n🔹 Select a file (number): ')

selected_file=$(ls "$target_folder" | sed -n "${file_choice}p")
if [ -z "$selected_file" ]; then
    echo -e "\n\033[1;31m[✘] Invalid selection. Exiting...\033[0m"
    exit 1
fi

selected_target_path="probe/$target_folder_name/$selected_file"
echo -e "\n✅ Selected Target File: \033[1;32m$selected_target_path\033[0m"

# Step 3: Trigger `404_1.go` with the selected file path
echo -e "\n🚀 \033[1;34mLaunching 404_1.go with Target:\033[0m \033[1;33m$selected_target_path\033[0m\n"
go run pkg/404_1.go "$selected_target_path"
