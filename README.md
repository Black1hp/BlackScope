# BlackScope - Subdomain Recon & Discovery Toolkit

![BlackScope Banner](https://github.com/Black1hp/BlackScope/blob/main/image.png?raw=true)

**BlackScope** is a powerful, multi-threaded subdomain reconnaissance and discovery toolkit crafted for bug bounty hunters, penetration testers, and red teamers. It automates subdomain enumeration for a target domain or a list of domains, leveraging popular tools like `subfinder`, `amass`, `assetfinder`, `findomain`, `sublist3r`, `crt.sh`, `dnscan`, and `ffuf`. BlackScope aggregates results, filters invalid entries, handles wildcard DNS records, and resolves subdomains with IP addresses, making it an essential tool for reconnaissance in authorized security testing environments such as bug bounty programs, CTFs, or personal labs.

## Features

- **Multi-Tool Subdomain Enumeration**: Integrates `subfinder`, `amass`, `assetfinder`, `findomain`, `sublist3r`, `crt.sh`, `dnscan`, and `ffuf` for comprehensive subdomain discovery.
- **Flexible Input**: Supports single domains (`-d`) or a file with multiple domains (`-f`).
- **Customizable Workflow**: Disable specific tools (e.g., `ffuf`, `dnscan`) with the `-disable` flag to comply with program restrictions or optimize performance.
- **Wildcard Handling**: Detects and saves wildcard DNS entries to `wildcards.txt` for analysis.
- **Clean Output**: Filters out invalid subdomains (e.g., IPs, wildcards) and aggregates results into `all_subs.txt`, `resolved_domains.txt`, and `resolved_ips_and_domains.txt`.
- **Thread-Safe Logging**: Logs errors to `Error.log` for easy debugging.
- **Verbose Mode**: Provides detailed output with the `-v` flag for troubleshooting.
- **Bug Bounty Optimized**: Filters `crt.sh` results for high-value subdomains (e.g., those containing `dev`, `api`, `test`, `stage`) likely to be of interest in bug bounty programs.

## Prerequisites

- **Go**: Requires Go 1.18 or later to compile and run the script.
- **Dependencies**: Ensure the following tools are installed and accessible in your `PATH`:
  - `subfinder`
  - `amass`
  - `assetfinder`
  - `findomain`
  - `sublist3r` (Python 3 with dependencies in `~/black1hp/Sublist3r/`)
  - `jq` (for parsing JSON from `crt.sh`)
  - `dnscan` (Python 3 script in `~/black1hp/dnscan/`)
  - `ffuf`
  - `dnsgen`
  - `dnsx`
- **Wordlist**: A subdomain wordlist (default: `~/SecLists/Discovery/DNS/subdomains-top1million-110000.txt` from [SecLists](https://github.com/danielmiessler/SecLists)).

## Installation

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/black1hp/BlackScope.git
   cd BlackScope
   ```

2. **Install Go**:
   Follow the [official Go installation guide](https://go.dev/doc/install) for your system.

3. **Install Dependencies**:
   Install the required tools:
   ```bash
   # Install subfinder
   go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

   # Install amass
   go install -v github.com/owasp-amass/amass/v4/...@master

   # Install assetfinder
   go install -v github.com/tomnomnom/assetfinder@latest

   # Install findomain
   cargo install findomain

   # Install sublist3r
   git clone https://github.com/aboul3la/Sublist3r.git ~/black1hp/Sublist3r
   cd ~/black1hp/Sublist3r
   pip3 install -r requirements.txt

   # Install jq
   sudo apt-get install jq  # On Debian/Ubuntu
   # Or use: brew install jq (macOS), dnf install jq (Fedora), etc.

   # Install dnscan
   git clone https://github.com/rbsec/dnscan.git ~/black1hp/dnscan
   cd ~/black1hp/dnscan
   pip3 install -r requirements.txt

   # Install ffuf
   go install -v github.com/ffuf/ffuf@latest

   # Install dnsgen
   pip3 install dnsgen

   # Install dnsx
   go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
   ```

4. **Set Up Wordlist**:
   Download SecLists or use your own wordlist:
   ```bash
   git clone https://github.com/danielmiessler/SecLists.git ~/SecLists
   ```

5. **Verify Setup**:
   Ensure all tools are in your `PATH`:
   ```bash
   subfinder --version
   amass --version
   assetfinder --version
   findomain --version
   python3 ~/black1hp/Sublist3r/sublist3r.py --version
   jq --version
   python3 ~/black1hp/dnscan/dnscan.py --version
   ffuf --version
   dnsgen --version
   dnsx --version
   ```

## Usage

Run BlackScope with a single domain or a file containing multiple domains. All commands assume you’re in the `BlackScope` directory.

### Single Domain
```bash
go run BlackScope.go -d target.com -v
```

### Multiple Domains
Create a `domains.txt` file:
```bash
echo -e "target1.com\ntarget2.com" > domains.txt
```
Run:
```bash
go run BlackScope.go -f domains.txt -v
```

### Disable Specific Tools
To skip active scanning tools (e.g., `ffuf`, `dnscan`) for sensitive targets:
```bash
go run BlackScope.go -d target.com -disable ffuf,dnscan -v
```

### Options
| Flag | Description | Default |
|------|-------------|---------|
| `-d`, `--domain` | Target domain | None |
| `-f`, `--file` | File with list of target domains | None |
| `-w`, `--wordlist` | Path to subdomain wordlist | `~/SecLists/Discovery/DNS/subdomains-top1million-110000.txt` |
| `-t`, `--threads` | Number of threads for `dnscan` | 300 |
| `-o`, `--output` | Output directory | `./results` |
| `-v`, `--verbose` | Enable verbose output | False |
| `-disable` | Comma-separated list of tools to disable (e.g., `ffuf,dnscan,subfinder`) | None |
| `-h`, `--help`, `-hh` | Show help | N/A |

### Output Structure
For each target domain, results are saved in `results/<domain>/`:
```
results/target.com/
├── all_subs.txt              # Aggregated unique subdomains
├── crt_raw.json             # Raw crt.sh JSON response
├── crt.txt                  # Filtered crt.sh subdomains (e.g., dev, api, test, stage)
├── subfinder.txt            # Subdomains from subfinder
├── amass.txt                # Subdomains from amass
├── assetfinder.txt          # Subdomains from assetfinder
├── findomain.txt            # Subdomains from findomain
├── sublist3r.txt            # Subdomains from sublist3r
├── bruteforce-dnscan.txt    # Subdomains from dnscan
├── bruteforce_subs.txt      # Cleaned dnscan subdomains
├── vhosts.json              # Virtual hosts from ffuf
├── vhosts.hosts             # Parsed ffuf hosts
├── permuted_subs.txt        # Permuted subdomains from dnsgen
├── resolved_subs.txt        # Resolved subdomains with IPs
├── resolved_domains.txt     # Resolved subdomains without IPs
├── resolved_ips_and_domains.txt # Full dnsx output
├── wildcards.txt            # Wildcard DNS entries
└── raw_subs.txt             # Unfiltered subdomains for debugging
```

Errors are logged to `Error.log` in the working directory.

## Notes for Bug Bounty Hunters

- **Ethical Use**: Use BlackScope only in authorized environments (e.g., bug bounty programs, CTFs, personal labs). Always respect program scopes and rules.
- **Wildcard Handling**: Check `wildcards.txt` to identify wildcard DNS entries and avoid false positives in reports.
- **High-Value Subdomains**: The `crt.sh` query filters for subdomains containing `dev`, `api`, `test`, or `stage`, which are often valuable targets in bug bounty programs.
- **Debugging**: Use `-v` for verbose output and check `raw_subs.txt` and `Error.log` if `all_subs.txt` is empty.
- **Optimization**: Disable active scanning tools (`ffuf`, `dnscan`) for sensitive targets using the `-disable` flag to comply with program restrictions.

## Troubleshooting

- **Empty `all_subs.txt`**: Check `raw_subs.txt` for unfiltered subdomains. Verify the base domain extraction and regex filtering in `Error.log`.
- **Crt.sh Errors**: Inspect `crt_raw.json` for the raw API response. If empty, check `Error.log` for connectivity issues or API changes.
- **Tool Failures**: Ensure all tools are installed and in your `PATH`. Run each tool manually to debug (e.g., `subfinder -d target.com`).
- **Wildcard Issues**: If `wildcards.txt` is empty, remove the `-q` flag from `dnscan` to capture verbose output:
  ```bash
  python3 ~/black1hp/dnscan/dnscan.py -d target.com -w ~/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -t 300
  ```

## Contributing

Contributions are welcome! Please submit a pull request or open an issue on GitHub for bug reports, feature requests, or improvements.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Author

- **Black1hp**
- GitHub: [github.com/black1hp](https://github.com/black1hp)

Happy Hunting! 💀
