#!/bin/bash


echo -e "\033[1;35m"
cat << "EOF"
  (\___/)
  (•ㅅ•)  
 ┏━∪∪━━━━┓
   K R D  
 SATANISM 
   SCANNER 
┗━━━━━━━━┛
EOF
echo -e "\033[0m"

echo -e "\033[1;31mKRD SATANISM - ULTIMATE SCANNER v1.0\033[0m"
echo "ONIONS: http://uww6ddtbjrjl264zjjvsgxdryzg2upmkq2wry5vkyjkhc34xyhtxpfad.onion"
echo "OSINT BOTS: @database_krd_bot @PhoneKrdBot"
echo -e "\033[1;33mDARK GODS GUIDE OUR VULNERABILITY SCANS\033[0m"
echo ""


GO_BIN_PATH="$HOME/go/bin"

trap ctrl_c INT
function ctrl_c() {
    echo -e "\n\033[1;31m[!] Ctrl+C detected. Exiting gracefully...\033[0m"
    save_state
    exit 1
}

save_state() {
    echo -e "\033[1;33m[+] Saving current state...\033[0m"
    echo "$target" > .last_target
    echo "$target_type" > .last_target_type
    echo -e "\033[1;32m[+] State saved. Resume with same target to continue.\033[0m"
}

install_tools() {
    echo -e "\033[1;34m[+] Checking required tools...\033[0m"
    
    if [[ ":$PATH:" != *":$GO_BIN_PATH:"* ]]; then
        export PATH="$PATH:$GO_BIN_PATH"
        echo "export PATH=\"\$PATH:$GO_BIN_PATH\"" >> ~/.bashrc
        source ~/.bashrc
    fi

    declare -A tools=(
        ["waybackurls"]="go install github.com/tomnomnom/waybackurls@latest"
        ["gau"]="go install github.com/lc/gau/v2/cmd/gau@latest"
        ["subfinder"]="go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        ["httpx"]="go install github.com/projectdiscovery/httpx/cmd/httpx@latest"
        ["anew"]="go install github.com/tomnomnom/anew@latest"
        ["gf"]="go install github.com/tomnomnom/gf@latest"
        ["nuclei"]="go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest"
        ["sqlmap"]="sudo apt install sqlmap -y"
        ["jq"]="sudo apt install jq -y"
    )

    for tool in "${!tools[@]}"; do
        if ! command -v "$tool" &> /dev/null && [ ! -f "$GO_BIN_PATH/$tool" ]; then
            echo -e "\033[1;33m[!] $tool not found. Installing...\033[0m"
            if [[ ${tools[$tool]} == pip* ]]; then
                eval "${tools[$tool]}" > /dev/null 2>&1
            elif [[ ${tools[$tool]} == apt* ]]; then
                sudo apt update > /dev/null 2>&1
                eval "${tools[$tool]}" > /dev/null 2>&1
            else
                go_path="${tools[$tool]}"
                eval "$go_path" > /dev/null 2>&1
            fi
            if command -v "$tool" &> /dev/null || [ -f "$GO_BIN_PATH/$tool" ]; then
                echo -e "\033[1;32m[✓] $tool installed successfully\033[0m"
            else
                echo -e "\033[1;31m[!] Failed to install $tool. Please install manually.\033[0m"
                exit 1
            fi
        else
            echo -e "\033[1;32m[✓] $tool already installed\033[0m"
        fi
    done

    if [ ! -d "$HOME/.gf" ]; then
        echo -e "\033[1;33m[+] Setting up GF patterns...\033[0m"
        git clone https://github.com/tomnomnom/gf > /dev/null 2>&1
        mkdir -p "$HOME/.gf"
        cp -r gf/examples/* "$HOME/.gf/"
        rm -rf gf
        echo -e "\033[1;32m[✓] GF patterns installed\033[0m"
    fi

    if [ ! -f "clean-patterns.txt" ]; then
        echo -e "\033[1;33m[+] Downloading SQLi patterns...\033[0m"
        wget -q "https://gist.githubusercontent.com/yashodhank/9962f1c4de86038cd9d462a8dc1dadef/raw/86c8de5653c9694dc1c1c67ab05e647b42f34e7b/Google%2520Dorks%2520for%2520SQL%2520Injection" -O sql-vuln-url.txt

        grep -v '^inurl:' sql-vuln-url.txt | sed 's/^inurl://' | grep -v '^$' > clean-patterns.txt
    fi

    if [ ! -f "AI.sh" ]; then
        echo -e "\033[1;33m[+] Creating AI.sh nuclei commands...\033[0m"
        cat > AI.sh << 'EOL'
#!/bin/bash
nuclei -list sub.txt -ai "Find web cache poisoning via 'Host', 'X-Forwarded-Host' and 'X-Forwarded-For' headers"
nuclei -list sub.txt -ai "Detect cache poisoning through 'X-Original-URL' and 'X-Rewrite-URL' headers"
nuclei -list sub.txt -ai "Identify cache poisoning by injecting payloads in 'Referer' and 'User-Agent'"
nuclei -list sub.txt -ai "Detect open Docker API endpoints allowing remote access"
nuclei -list sub.txt -ai "Detect exposed Kubernetes API servers allowing unauthenticated access"
nuclei -list sub.txt -ai "Find open Kubernetes Dashboard instances with weak or no authentication"
nuclei -list sub.txt -ai "Scan for cloud metadata endpoints accessible externally"
nuclei -list sub.txt -ai "Scan for exposed environment files (.env) containing credentials"
nuclei -list sub.txt -ai "Find open directory listings and publicly accessible files"
nuclei -list sub.txt -ai "Detect exposed .git repositories and sensitive files"
nuclei -list sub.txt -ai "Identify publicly accessible backup and log files (.log, .bak, .sql, .dump)"
nuclei -list sub.txt -ai "Detect exposed .htaccess and .htpasswd files"
nuclei -list sub.txt -ai "Check for SSH private keys leaked in web directories"
nuclei -list sub.txt -ai "Find exposed API keys and secrets in responses and URLs"
nuclei -list sub.txt -ai "Identify API endpoints leaking sensitive data"
nuclei -list sub.txt -ai "Find leaked database credentials in JavaScript files"
nuclei -list sub.txt -ai "Detect debug endpoints revealing system information"
nuclei -list sub.txt -ai "Identify test and staging environments exposed to the internet"
nuclei -list sub.txt -ai "Find admin login endpoints, filter 404 response code"
nuclei -list sub.txt -ai "Detect exposed stack traces in error messages"
nuclei -list sub.txt -ai "Identify default credentials on login pages"
nuclei -list sub.txt -ai "Find misconfigured Apache/Nginx security headers"
nuclei -list sub.txt -ai "Find sensitive information in HTML comments (debug notes, API keys, credentials)"
nuclei -list sub.txt -ai "Find exposed .env files leaking credentials, API keys, and database passwords"
nuclei -list sub.txt -ai "Find exposed configuration files such as config.json, config.yaml, config.php, application.properties containing API keys and database credentials."
nuclei -list sub.txt -ai "Find exposed database configuration files such as database.yml, db_config.php, .pgpass, .my.cnf leaking credentials."
nuclei -list sub.txt -ai "Find exposed Docker and Kubernetes configuration files such as docker-compose.yml, kubeconfig, .dockercfg, .docker/config.json containing cloud credentials and secrets."
nuclei -list sub.txt -ai "Find exposed SSH keys and configuration files such as id_rsa, authorized_keys, and ssh_config."
nuclei -list sub.txt -ai "Find exposed WordPress configuration files (wp-config.php) containing database credentials and authentication secrets."
nuclei -list sub.txt -ai "Identify open directory listings exposing sensitive files"
nuclei -list sub.txt -ai "Find exposed .git directories allowing full repo download"
nuclei -list sub.txt -ai "Find exposed .svn and .hg repositories leaking source code"
nuclei -list sub.txt -ai "Identify open FTP servers allowing anonymous access"
nuclei -list sub.txt -ai "Extract page title, detect tech and versions"
nuclei -list sub.txt -ai "Extract email addresses from web pages"
nuclei -list sub.txt -ai "Extract all subdomains referenced in web pages"
EOL
        chmod +x AI.sh
        echo -e "\033[1;32m[✓] AI.sh created with nuclei commands\033[0m"
    fi
}

get_tool_path() {
    local tool=$1

    if [ -f "$GO_BIN_PATH/$tool" ]; then
        echo "$GO_BIN_PATH/$tool"

    elif command -v "$tool" &> /dev/null; then
        echo "$tool"
    else
        echo ""
    fi
}


run_tool() {
    local tool_name=$1
    local command=$2
    local output=$3
    local message=$4
    
    echo -e "\033[1;34m$message\033[0m"
    

    eval "$command" 2> /tmp/tool_error.log
    local exit_code=$?
    
    if [ $exit_code -ne 0 ]; then
        echo -e "\033[1;31m[!] Error running $tool_name (Exit code: $exit_code)\033[0m"
        echo -e "\033[1;33mError output:\033[0m"
        cat /tmp/tool_error.log
        rm -f /tmp/tool_error.log
        return 1
    fi
    rm -f /tmp/tool_error.log

    if [ -f "$output" ] && [ ! -s "$output" ]; then
        rm -f "$output"
        echo -e "\033[1;33m[!] No results from $tool_name. Output file removed.\033[0m"
        return 1
    fi
    
    return 0
}

scan_domain() {
    local domain=$1
    local results_dir="results/$domain"
    mkdir -p "$results_dir"
    SUBFINDER=$(get_tool_path "subfinder")
    HTTPX=$(get_tool_path "httpx")
    WAYBACKURLS=$(get_tool_path "waybackurls")
    GAU=$(get_tool_path "gau")
    GF=$(get_tool_path "gf")
    NUCLEI=$(get_tool_path "nuclei")
    ANEW=$(get_tool_path "anew")
    JQ=$(get_tool_path "jq")
    
    run_tool "subfinder" "$SUBFINDER -d '$domain' -o '$results_dir/subdomains.txt' -silent" \
        "$results_dir/subdomains.txt" "[1/8] Discovering subdomains..."
    
    if [ -f "$results_dir/subdomains.txt" ]; then
        run_tool "crt.sh" "curl -s 'https://crt.sh/?q=$domain&output=json' | $JQ -r '.[].name_value' | grep -Po '(\w+\.\w+\.\w+)$' | $ANEW '$results_dir/subdomains.txt'" \
            "$results_dir/subdomains.txt" "[+] Adding crt.sh subdomains..."
    fi
    
    if [ -f "$results_dir/subdomains.txt" ]; then
        run_tool "httpx" "cat '$results_dir/subdomains.txt' | $HTTPX -ports 80,443,8080,8000,8888,8443,4443,444,9443,10443 -threads $threads -silent -o '$results_dir/activesubs.txt'" \
            "$results_dir/activesubs.txt" "[2/8] Scanning ports and finding active subdomains..."
    fi
    
    if [ -f "$results_dir/activesubs.txt" ]; then
        run_tool "waybackurls" "cat '$results_dir/activesubs.txt' | $WAYBACKURLS | $ANEW '$results_dir/wayback.txt'" \
            "$results_dir/wayback.txt" "[3/8] Gathering Wayback Machine URLs..."
    fi
    
    if [ -f "$results_dir/activesubs.txt" ]; then
        run_tool "gau" "cat '$results_dir/activesubs.txt' | $GAU | $ANEW '$results_dir/gau.txt'" \
            "$results_dir/gau.txt" "[4/8] Gathering URLs with GAU..."
    fi
    
    if [ -f "$results_dir/wayback.txt" ] || [ -f "$results_dir/gau.txt" ]; then
        cat "$results_dir"/{wayback,gau}.txt 2>/dev/null | sort -u > "$results_dir/all_urls.txt"
        echo -e "\033[1;32m[+] Found $(wc -l < "$results_dir/all_urls.txt") URLs\033[0m"
    else
        echo -e "\033[1;33m[!] No URLs found. Skipping URL processing steps.\033[0m"
        touch "$results_dir/all_urls.txt"
    fi
    
    if [ -s "$results_dir/all_urls.txt" ]; then
        run_tool "httpx" "cat '$results_dir/all_urls.txt' | $HTTPX -ports 80,443,8080,8000,8888 -threads $threads -silent -o '$results_dir/live_urls.txt'" \
            "$results_dir/live_urls.txt" "[5/8] Finding live URLs..."
    else
        echo -e "\033[1;33m[!] No URLs to test. Skipping live URL check.\033[0m"
        touch "$results_dir/live_urls.txt"
    fi
    
    echo -e "\033[1;35m[6/8] Scanning for SQL injection vulnerabilities...\033[0m"
    if [ -f "clean-patterns.txt" ] && [ -s "$results_dir/live_urls.txt" ]; then

        grep -iF -f clean-patterns.txt "$results_dir/live_urls.txt" > "$results_dir/sqli_targets.txt"
        
        if [ -s "$results_dir/sqli_targets.txt" ]; then
            echo -e "\033[1;32m[+] Found $(wc -l < "$results_dir/sqli_targets.txt") potential SQLi targets\033[0m"

            echo -e "\033[1;36m\n[+] SQLMAP COMMANDS FOR FOUND TARGETS:\033[0m"
            echo -e "\033[1;33m# Run these commands to test for SQL injection:\033[0m"
            counter=1
            while read -r url; do
                echo "sqlmap -u '$url' --batch --risk=3 --level=5 --dbs --random-agent --threads=10 --technique=BEUSTQ -o"
                echo "# Save results:"
                echo "sqlmap -u '$url' --batch --risk=3 --level=5 --dbs --random-agent --threads=10 --technique=BEUSTQ --output-dir=$results_dir/sqlmap_$counter"
                counter=$((counter+1))
            done < "$results_dir/sqli_targets.txt"

            if [ "$auto_sqlmap" == "y" ]; then
                echo -e "\033[1;33m[+] Automatically running SQLMap on found targets...\033[0m"
                counter=1
                while read -r url; do
                    echo -e "\n\033[1;34m[+] Testing: $url\033[0m"
                    sqlmap -u "$url" --batch --risk=3 --level=5 --dbs --random-agent \
                        --threads=10 --technique=BEUSTQ --output-dir="$results_dir/sqlmap_$counter"
                    counter=$((counter+1))
                done < "$results_dir/sqli_targets.txt"
            fi
        else
            echo -e "\033[1;33m[!] No SQLi targets found\033[0m"
        fi
    else
        echo -e "\033[1;33m[!] Clean patterns missing or no live URLs for SQLi scanning\033[0m"
    fi
    
    echo -e "\033[1;35m[7/8] Running Nuclei vulnerability scans...\033[0m"
    if [ -f "$results_dir/activesubs.txt" ]; then
        $NUCLEI -list "$results_dir/activesubs.txt" -severity critical,high -o "$results_dir/nuclei_subdomains.txt" -silent -concurrency $parallel_jobs
    else
        echo -e "\033[1;33m[!] No active subdomains for nuclei scan\033[0m"
    fi
    
    if [ -f "$results_dir/live_urls.txt" ]; then
        $NUCLEI -list "$results_dir/live_urls.txt" -severity critical,high -o "$results_dir/nuclei_urls.txt" -silent -concurrency $parallel_jobs
    else
        echo -e "\033[1;33m[!] No live URLs for nuclei scan\033[0m"
    fi
    
    echo -e "\033[1;35m[8/8] Running advanced nuclei scans...\033[0m"
    if [ -f "$results_dir/activesubs.txt" ]; then
        cp "$results_dir/activesubs.txt" sub.txt
        ./AI.sh > "$results_dir/ai_results.txt" 2>/dev/null
        rm -f sub.txt
    else
        echo -e "\033[1;33m[!] No active subdomains for advanced nuclei scan\033[0m"
    fi
    
    find "$results_dir" -type f -empty -delete
    save_state
    
    echo -e "\n\033[1;32m[+] Scan complete! Results saved to: $results_dir\033[0m"
    echo -e "\033[1;36mFiles created:"
    tree -C "$results_dir" || ls -R "$results_dir"
    echo -e "\033[0m"
    
    if [ -f "$results_dir/nuclei_subdomains.txt" ]; then
        echo -e "\033[1;31m[!] CRITICAL FINDINGS IN SUBDOMAINS:\033[0m"
        grep -E 'high|critical' "$results_dir/nuclei_subdomains.txt" | head -n 5
    fi
    
    if [ -f "$results_dir/nuclei_urls.txt" ]; then
        echo -e "\n\033[1;31m[!] CRITICAL FINDINGS IN URLS:\033[0m"
        grep -E 'high|critical' "$results_dir/nuclei_urls.txt" | head -n 5
    fi
    
    if [ -f "$results_dir/sqli_targets.txt" ]; then
        echo -e "\n\033[1;31m[!] SQL INJECTION TARGETS FOUND:\033[0m"
        head -n 5 "$results_dir/sqli_targets.txt"
    fi
}

install_tools

echo -e "\033[1;34m[?] Are you running on a virtual machine? (y/n):\033[0m"
read is_vm

echo -e "\033[1;34m[?] Scan speed? (fast/medium/slow):\033[0m"
read scan_speed

if [ "$is_vm" == "y" ]; then
    threads=50
    parallel_jobs=5
    echo -e "\033[1;33m[+] Virtual machine detected. Using conservative resource settings.\033[0m"
else
    case $scan_speed in
        fast)
            threads=200
            parallel_jobs=20
            echo -e "\033[1;33m[+] Fast mode enabled. Aggressive resource usage.\033[0m"
            ;;
        medium)
            threads=100
            parallel_jobs=10
            echo -e "\033[1;33m[+] Medium speed selected. Balanced resource usage.\033[0m"
            ;;
        *)
            threads=50
            parallel_jobs=5
            echo -e "\033[1;33m[+] Slow mode enabled. Conservative resource usage.\033[0m"
            ;;
    esac
fi

if [ -f ".last_target" ] && [ -f ".last_target_type" ]; then
    last_target=$(<.last_target)
    last_target_type=$(<.last_target_type)
    echo -e "\033[1;33m[+] Found previous scan for $last_target_type: $last_target\033[0m"
    read -p "[?] Resume scan? (y/n): " resume_choice
    if [ "$resume_choice" == "y" ]; then
        target=$last_target
        target_type=$last_target_type
        echo -e "\033[1;32m[+] Resuming from saved state\033[0m"
    fi
fi

if [ -z "$target" ]; then
    echo -e "\033[1;34m[?] Scan type? (single/file):\033[0m"
    read target_type
    
    case $target_type in
        single)
            echo -e "\033[1;34m[?] Enter target domain (e.g., example.com):\033[0m"
            read target
            ;;
        file)
            echo -e "\033[1;34m[?] Enter path to domains file (e.g., domains.txt):\033[0m"
            read target_file
            if [ ! -f "$target_file" ]; then
                echo -e "\033[1;31m[!] File not found. Exiting.\033[0m"
                exit 1
            fi
            target="$target_file"
            ;;
        *)
            echo -e "\033[1;31m[!] Invalid choice. Exiting.\033[0m"
            exit 1
            ;;
    esac
fi

echo -e "\033[1;34m[?] Automatically run SQLMap on found SQLi targets? (y/n):\033[0m"
read auto_sqlmap

if [ "$target_type" == "file" ]; then
    echo -e "\033[1;35m[+] Scanning multiple domains from file: $target\033[0m"
    while IFS= read -r domain; do
        echo -e "\n\033[1;33m[+] Scanning domain: $domain\033[0m"
        scan_domain "$domain"
    done < "$target"
else
    echo -e "\033[1;35m[+] Scanning single domain: $target\033[0m"
    scan_domain "$target"
fi


echo -e "\n\033[1;35mMAY THE DARK GODS BLESS YOUR VULNERABILITY FINDINGS!"
echo -e "ALL HAIL THE KRD SATANISM COLLECTIVE!\033[0m"
