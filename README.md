# SQL-INJECTION-SCANNER
this bash file can search for vuln SQL INJECTION via URLs, And also finding subdomains, alive ones, automattically scan the single/file domain and search for vulnable url.


# KRD Scanner - Vulnerability Assessment Tool

## Installation
```bash
git clone https://github.com/furry-execute/SQL-INJECTION-SCANNER.git
cd SQL-INJECTION-SCANNER
chmod +x SCANNER.sh
./SCANNER.sh
```

## Usage
1. Run the scanner:
```bash
./SCANNER.sh
```

2. Follow the prompts:
- Select scan speed (fast/medium/slow)
- Choose target type (single domain or file)
- Decide on automatic SQLMap testing (y/n)

## Features
- Subdomain discovery (Subfinder + crt.sh)
- URL harvesting (Wayback + GAU)
- SQL injection detection
- Automated vulnerability scanning (Nuclei)
- Scan resumption capability
- Resource optimization (auto-detects VM/host)

## If the script didn't Downloaded use this command instead:
```
( command -v pkg >/dev/null && echo "[+] Termux detected" && pkg update -y && pkg install -y golang git jq sqlmap && go install github.com/tomnomnom/waybackurls@latest && go install github.com/lc/gau/v2/cmd/gau@latest && go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && go install github.com/projectdiscovery/httpx/cmd/httpx@latest && go install github.com/tomnomnom/anew@latest && go install github.com/tomnomnom/gf@latest && go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest ) || ( echo "[+] Rooted Linux detected" && sudo apt update -y && sudo apt install -y golang-go git jq sqlmap && go install github.com/tomnomnom/waybackurls@latest && go install github.com/lc/gau/v2/cmd/gau@latest && go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && go install github.com/projectdiscovery/httpx/cmd/httpx@latest && go install github.com/tomnomnom/anew@latest && go install github.com/tomnomnom/gf@latest && go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest )

```

## Output Structure
```
results/
└── target.com/
    ├── activesubs.txt
    ├── nuclei_results.txt
    ├── sqli_targets.txt
    └── sqlmap_reports/
```

## Dependencies (Auto-Installed)
- Required tools: Subfinder, httpx, waybackurls, gau, nuclei, gf
- System packages: sqlmap, jq

## Important Notes
- Use only on authorized systems
- Results are saved in the 'results' directory
- Press Ctrl+C to pause scanning
- Previous scans can be resumed
