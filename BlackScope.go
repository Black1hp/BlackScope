package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

type Config struct {
	Domain      string
	Domains     []string
	Wordlist    string
	Threads     int
	Output      string
	Verbose     bool
	DisableTools map[string]bool
}

var errorLog *os.File

// Initialize error log file
func initErrorLog() {
	var err error
	errorLog, err = os.OpenFile("Error.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		log.Fatalf("Failed to open Error.log: %v", err)
	}
}

// Log errors to Error.log with thread safety
func logError(message string) {
	logMutex := sync.Mutex{}
	logMutex.Lock()
	defer logMutex.Unlock()
	errorLog.WriteString(message + "\n")
}

// Display script banner
func banner() {
	fmt.Println(`
__________.__                 __      _________
\______   \  | _____    ____ |  | __ /   _____/ ____  ____ ______   ____
 |    |  _/  | \__  \ _/ ___\|  |/ / \_____  \_/ ___\/  _ \\____ \_/ __ \
 |    |   \  |__/ __ \\  \___|    <  /        \  \__(  <_> )  |_> >  ___/
 |______  /____(____  /\___  >__|_ \/_______  /\___  >____/|   __/ \___  >
        \/          \/     \/     \/        \/     \/      |__|        \/

        BlackScope — Subdomain Recon & Discovery Toolkit
        Author: Black1hp | github.com/black1hp
    `)
}

// Print usage instructions
func printHelp() {
	fmt.Println(`
Usage:
  recon -d target.com [options]
  recon -f domains.txt [options]

Options:
  -d, --domain      Target domain
  -f, --file        File containing list of target domains
  -w, --wordlist    Wordlist path (default: ~/SecLists/Discovery/DNS/subdomains-top1million-110000.txt)
  -t, --threads     Number of threads (default: 300)
  -o, --output      Output directory (default: ./results)
  -v, --verbose     Enable verbose output
  -disable          Comma-separated list of tools to disable (e.g., ffuf,dnscan,subfinder)
                    Supported tools: subfinder, amass, assetfinder, findomain, sublist3r, crtsh, dnscan, ffuf
  -h, --help, -hh   Show this help page

Example:
  go run BlackScope.go -d target.com -v
  go run BlackScope.go -f domains.txt -disable ffuf,dnscan -v
`)
}

// Read domains from file
func readDomainsFromFile(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open domains file: %v", err)
	}
	defer file.Close()

	var domains []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		domain := strings.TrimSpace(scanner.Text())
		if domain != "" && !strings.HasPrefix(domain, "#") {
			if !strings.ContainsAny(domain, "/;\"'`|&") {
				domains = append(domains, domain)
			} else {
				logError(fmt.Sprintf("Invalid domain in file: %s", domain))
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading domains file: %v", err)
	}
	return domains, nil
}

// Extract base domain (e.g., example.com from sub.example.com)
func getBaseDomain(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) <= 2 {
		return domain
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

// Parse command-line flags
func parseFlags() *Config {
	knownFlags := []string{"-d", "--domain", "-f", "--file", "-w", "--wordlist", "-t", "--threads", "-o", "--output", "-v", "-disable", "-h", "--help", "-hh"}
	for _, arg := range os.Args[1:] {
		if strings.HasPrefix(arg, "-") {
			valid := false
			for _, known := range knownFlags {
				if arg == known {
					valid = true
					break
				}
			}
			if !valid {
				fmt.Printf("Unknown flag: %s\n", arg)
				printHelp()
				os.Exit(1)
			}
		}
	}

	var cfg Config
	var domainsFile string
	var disableTools string
	flag.StringVar(&cfg.Domain, "d", "", "Target domain")
	flag.StringVar(&cfg.Domain, "domain", "", "Target domain")
	flag.StringVar(&domainsFile, "f", "", "File containing list of target domains")
	flag.StringVar(&domainsFile, "file", "", "File containing list of target domains")
	flag.StringVar(&cfg.Wordlist, "w", os.Getenv("HOME")+"/SecLists/Discovery/DNS/subdomains-top1million-110000.txt", "Wordlist path")
	flag.StringVar(&cfg.Wordlist, "wordlist", os.Getenv("HOME")+"/SecLists/Discovery/DNS/subdomains-top1million-110000.txt", "Wordlist path")
	flag.IntVar(&cfg.Threads, "t", 300, "Number of threads")
	flag.IntVar(&cfg.Threads, "threads", 300, "Number of threads")
	flag.StringVar(&cfg.Output, "o", "./results", "Output directory")
	flag.StringVar(&cfg.Output, "output", "./results", "Output directory")
	flag.BoolVar(&cfg.Verbose, "v", false, "Verbose output")
	flag.BoolVar(&cfg.Verbose, "verbose", false, "Verbose output")
	flag.StringVar(&disableTools, "disable", "", "Comma-separated list of tools to disable")

	help := flag.Bool("h", false, "Help")
	help2 := flag.Bool("help", false, "Help")
	help3 := flag.Bool("hh", false, "Help")

	flag.Parse()

	if *help || *help2 || *help3 {
		printHelp()
		os.Exit(0)
	}

	if cfg.Domain != "" && domainsFile != "" {
		fmt.Println("Error: Specify either -d (single domain) or -f (domains file), not both")
		printHelp()
		os.Exit(1)
	}

	if cfg.Domain == "" && domainsFile == "" {
		fmt.Println("Error: Must specify either -d (single domain) or -f (domains file)")
		printHelp()
		os.Exit(1)
	}

	cfg.DisableTools = make(map[string]bool)
	if disableTools != "" {
		validTools := map[string]bool{
			"subfinder":  true,
			"amass":      true,
			"assetfinder": true,
			"findomain":  true,
			"sublist3r":  true,
			"crtsh":      true,
			"dnscan":     true,
			"ffuf":       true,
		}
		for _, tool := range strings.Split(strings.ToLower(disableTools), ",") {
			tool = strings.TrimSpace(tool)
			if _, ok := validTools[tool]; !ok {
				logError(fmt.Sprintf("Invalid tool to disable: %s. Supported tools: subfinder, amass, assetfinder, findomain, sublist3r, crtsh, dnscan, ffuf", tool))
				fmt.Printf("Warning: Invalid tool '%s' ignored. See Error.log for details.\n", tool)
			} else {
				cfg.DisableTools[tool] = true
			}
		}
	}

	if domainsFile != "" {
		var err error
		cfg.Domains, err = readDomainsFromFile(domainsFile)
		if err != nil {
			log.Fatalf("Failed to read domains file: %v", err)
		}
		if len(cfg.Domains) == 0 {
			fmt.Println("Error: No valid domains found in the file")
			os.Exit(1)
		}
	} else {
		if strings.ContainsAny(cfg.Domain, "/;\"'`|&") {
			fmt.Println("Invalid domain format. Use example.com")
			os.Exit(1)
		}
		cfg.Domains = []string{cfg.Domain}
	}

	return &cfg
}

// Execute a shell command with enhanced error handling
func runCommand(cmdStr string, cfg *Config) {
	if cfg.Verbose {
		fmt.Println("[RUNNING] ", cmdStr)
	}
	cmd := exec.Command("bash", "-c", cmdStr)
	output, err := cmd.CombinedOutput()
	if err != nil {
		logError(fmt.Sprintf("Command failed: %s | Error: %v | Output: %s", cmdStr, err, string(output)))
	} else if cfg.Verbose {
		fmt.Println("[OUTPUT] ", string(output))
	}
	if len(output) == 0 && err == nil {
		logError(fmt.Sprintf("Command produced no output: %s", cmdStr))
	}
	parts := strings.Fields(cmdStr)
	var outputFile string
	for i, part := range parts {
		if part == ">" && i+1 < len(parts) {
			outputFile = parts[i+1]
			break
		}
	}
	if outputFile != "" {
		if stat, err := os.Stat(outputFile); err == nil && stat.Size() == 0 {
			logError(fmt.Sprintf("Output file is empty: %s", outputFile))
		} else if err != nil && os.IsNotExist(err) {
			logError(fmt.Sprintf("Output file not created: %s", outputFile))
		}
	}
}

// Perform subdomain reconnaissance
func reconDomain(domain string, cfg *Config) {
	fmt.Println("Starting recon for:", domain)
	dir := filepath.Join(cfg.Output, domain)
	os.MkdirAll(dir, os.ModePerm)

	// Extract base domain for filtering
	baseDomain := getBaseDomain(domain)
	// Escape dots for regex
	baseDomainRegex := strings.ReplaceAll(baseDomain, ".", "\\.")

	var wg sync.WaitGroup

	// Parallel recon tools
	tools := []string{}
	if !cfg.DisableTools["subfinder"] {
		tools = append(tools, fmt.Sprintf("subfinder -d %s -all --recursive -o %s/subfinder.txt", domain, dir))
	}
	if !cfg.DisableTools["amass"] {
		tools = append(tools, fmt.Sprintf("amass enum -passive -d %s -o %s/amass.txt -v", domain, dir))
	}
	if !cfg.DisableTools["assetfinder"] {
		tools = append(tools, fmt.Sprintf("assetfinder --subs-only %s | tee %s/assetfinder.txt", domain, dir))
	}
	if !cfg.DisableTools["findomain"] {
		tools = append(tools, fmt.Sprintf("findomain -t %s -u %s/findomain.txt", domain, dir))
	}
	if !cfg.DisableTools["sublist3r"] {
		tools = append(tools, fmt.Sprintf("python3 ~/black1hp/Sublist3r/sublist3r.py -d %s -o %s/sublist3r.txt", domain, dir))
	}
	if !cfg.DisableTools["crtsh"] {
		tools = append(tools, fmt.Sprintf(`curl -s -w "%%{http_code}" "https://crt.sh/?q=%s&output=json" > %s/crt_raw.json`, baseDomain, dir))
		tools = append(tools, fmt.Sprintf(`cat %s/crt_raw.json | grep -v "^000" | jq -r '.[] | select(.name_value | type == "string") | .name_value | select(. | test("dev|api|test|stage"; "i"))' | sort -u > %s/crt.txt || cat %s/crt_raw.json | grep -v "^000" | jq -r '.[] | select(.name_value | type == "string") | .name_value' | sort -u > %s/crt.txt`, dir, dir, dir, dir))
		// Fallback to CertSpotter
		tools = append(tools, fmt.Sprintf(`[ -s %s/crt.txt ] || curl -s "https://api.certspotter.com/v1/issuances?domain=%s&include_subdomains=true&expand=dns_names" | jq -r '.[].dns_names[]' | sort -u > %s/certspotter.txt`, dir, baseDomain, dir))
	}
	if !cfg.DisableTools["dnscan"] {
		tools = append(tools, fmt.Sprintf("python3 ~/black1hp/dnscan/dnscan.py -d %s -w %s -t %d | tee %s/bruteforce-dnscan.txt", domain, cfg.Wordlist, cfg.Threads, dir))
	}
	if !cfg.DisableTools["ffuf"] {
		tools = append(tools, fmt.Sprintf(`ffuf -H "Host: FUZZ.%s" -u https://%s/ -w %s -mc 200,302 -o %s/vhosts.json -noninteractive`, domain, domain, cfg.Wordlist, dir))
	}

	for _, c := range tools {
		wg.Add(1)
		go func(cmd string) {
			defer wg.Done()
			runCommand(cmd, cfg)
		}(c)
	}
	wg.Wait()

	// Explicitly list input files for raw_subs.txt
	inputFiles := []string{
		"subfinder.txt",
		"amass.txt",
		"assetfinder.txt",
		"findomain.txt",
		"sublist3r.txt",
		"crt.txt",
		"certspotter.txt",
		"bruteforce-dnscan.txt",
		"vhosts.hosts",
	}
	var validFiles []string
	for _, file := range inputFiles {
		path := filepath.Join(dir, file)
		if stat, err := os.Stat(path); err == nil && stat.Size() > 0 {
			validFiles = append(validFiles, path)
			logError BESOIN D'UN FICHIER
logError(fmt.Sprintf("Input file for raw_subs.txt: %s (%d bytes)", path, stat.Size()))
		}
	}

	// Sequential post-processing
	sequential := []string{}
	if !cfg.DisableTools["dnscan"] {
		sequential = append(sequential,
			fmt.Sprintf(`[ -f %s/bruteforce-dnscan.txt ] && grep -E 'Wildcard domain found' %s/bruteforce-dnscan.txt > %s/wildcards.txt || echo "No dnscan output" > %s/wildcards.txt`, dir, dir, dir, dir),
			fmt.Sprintf(`[ -f %s/bruteforce-dnscan.txt ] && grep -vE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+|^\\*|^\\[\\*\\]|^\\[-\\]' %s/bruteforce-dnscan.txt > %s/bruteforce_subs.txt || touch %s/bruteforce_subs.txt`, dir, dir, dir, dir),
		)
	}
	if !cfg.DisableTools["ffuf"] {
		sequential = append(sequential,
			fmt.Sprintf(`[ -f %s/vhosts.json ] && jq -r '.results[].host' %s/vhosts.json | sort -u > %s/vhosts.hosts || touch %s/vhosts.hosts`, dir, dir, dir, dir),
		)
	}
	// Aggregate subdomains explicitly
	if len(validFiles) > 0 {
		sequential = append(sequential,
			fmt.Sprintf(`cat %s 2>/dev/null > %s/raw_subs.txt`, strings.Join(validFiles, " "), dir),
			fmt.Sprintf(`[ -s %s/raw_subs.txt ] && cat %s/raw_subs.txt | grep -vE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+|^\\*|^\\[\\*\\]|^\\[-\\]' | grep -E '^[a-zA-Z0-9][a-zA-Z0-9.-]*\\.%s$' | sort -u > %s/all_subs.txt || touch %s/all_subs.txt`, dir, dir, baseDomainRegex, dir, dir),
		)
	} else {
		sequential = append(sequential,
			fmt.Sprintf(`touch %s/raw_subs.txt`, dir),
			fmt.Sprintf(`touch %s/all_subs.txt`, dir),
		)
	}
	sequential = append(sequential,
		fmt.Sprintf(`[ -s %s/all_subs.txt ] && dnsgen %s/all_subs.txt -w %s | grep -E '^[a-zA-Z0-9][a-zA-Z0-9.-]*\\.%s$' | sort -u > %s/permuted_subs.txt || touch %s/permuted_subs.txt`, dir, dir, cfg.Wordlist, baseDomainRegex, dir, dir),
		fmt.Sprintf(`[ -s %s/permuted_subs.txt ] && dnsx -l %s/permuted_subs.txt -resp -o %s/resolved_subs.txt || touch %s/resolved_subs.txt`, dir, dir, dir, dir),
		fmt.Sprintf(`[ -s %s/resolved_subs.txt ] && awk -F' - ' '{if (NF > 1) print $2; else print $1}' %s/resolved_subs.txt > %s/resolved_domains.txt || touch %s/resolved_domains.txt`, dir, dir, dir, dir),
		fmt.Sprintf(`[ -s %s/resolved_subs.txt ] && cat %s/resolved_subs.txt > %s/resolved_ips_and_domains.txt || touch %s/resolved_ips_and_domains.txt`, dir, dir, dir, dir),
		fmt.Sprintf(`wc -l %s/all_subs.txt`, dir),
	)

	for _, c := range sequential {
		runCommand(c, cfg)
	}

	// Log which tools produced output
	for _, file := range inputFiles {
		path := filepath.Join(dir, file)
		if stat, err := os.Stat(path); err == nil && stat.Size() > 0 {
			logError(fmt.Sprintf("Tool output found: %s (%d bytes)", path, stat.Size()))
		} else if err == nil {
			logError(fmt.Sprintf("Tool output empty: %s", path))
		} else {
			logError(fmt.Sprintf("Tool output missing: %s", path))
		}
	}

	// Summary of subdomains
	summaryFile := filepath.Join(dir, "summary.txt")
	f, err := os.Create(summaryFile)
	if err != nil {
		logError(fmt.Sprintf("Failed to create summary file: %v", err))
	}
	defer f.Close()
	subsFile := filepath.Join(dir, "all_subs.txt")
	if stat, err := os.Stat(subsFile); err == nil && stat.Size() > 0 {
		cmd := exec.Command("bash", "-c", fmt.Sprintf(`wc -l %s`, subsFile))
		output, _ := cmd.CombinedOutput()
		f.WriteString(fmt.Sprintf("Domain: %s, Total subdomains: %s", domain, string(output)))
	} else {
		f.WriteString(fmt.Sprintf("Domain: %s, No subdomains found\n", domain))
	}

	fmt.Println("Recon completed for", domain, ". Results saved in", dir)
	if stat, _ := os.Stat("Error.log"); stat.Size() > 0 {
		fmt.Println("⚠️  Some errors occurred. Check Error.log for details.")
	}
	if _, err := os.Stat(filepath.Join(dir, "wildcards.txt")); err == nil {
		fmt.Println("Wildcard DNS entries saved in", filepath.Join(dir, "wildcards.txt"))
	}
}

func main() {
	banner()
	initErrorLog()
	defer errorLog.Close()

	cfg := parseFlags()

	for _, domain := range cfg.Domains {
		reconDomain(domain, cfg)
	}
}
