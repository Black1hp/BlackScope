package main

import (
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
	Domain   string
	Wordlist string
	Threads  int
	Output   string
	Verbose  bool
}

var errorLog *os.File

func initErrorLog() {
	var err error
	errorLog, err = os.OpenFile("Error.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		log.Fatalf("Failed to open Error.log: %v", err)
	}
}

func logError(message string) {
	errorLog.WriteString(message + "\n")
}

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


func printHelp() {
	fmt.Println(`
Usage:
  recon -d target.com [options]

Options:
  -d, --domain      Target domain (required)
  -w, --wordlist    Wordlist path (default: ~/SecLists/Discovery/DNS/subdomains-top1million-110000.txt)
  -t, --threads     Number of threads (default: 300)
  -o, --output      Output directory (default: ./results)
  -v, --verbose     Enable verbose output
  -h, --help, -hh   Show this help page

Example:
  recon -d facebook.com -v
`)
}

func parseFlags() *Config {
	knownFlags := []string{"-d", "--domain", "-w", "--wordlist", "-t", "--threads", "-o", "--output", "-v", "-h", "--help", "-hh"}
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
	flag.StringVar(&cfg.Domain, "d", "", "Target domain")
	flag.StringVar(&cfg.Domain, "domain", "", "Target domain")
	flag.StringVar(&cfg.Wordlist, "w", os.Getenv("HOME")+"/SecLists/Discovery/DNS/subdomains-top1million-110000.txt", "Wordlist path")
	flag.StringVar(&cfg.Wordlist, "wordlist", os.Getenv("HOME")+"/SecLists/Discovery/DNS/subdomains-top1million-110000.txt", "Wordlist path")
	flag.IntVar(&cfg.Threads, "t", 300, "Number of threads")
	flag.IntVar(&cfg.Threads, "threads", 300, "Number of threads")
	flag.StringVar(&cfg.Output, "o", "./results", "Output directory")
	flag.StringVar(&cfg.Output, "output", "./results", "Output directory")
	flag.BoolVar(&cfg.Verbose, "v", false, "Verbose output")
	flag.BoolVar(&cfg.Verbose, "verbose", false, "Verbose output")

	help := flag.Bool("h", false, "Help")
	help2 := flag.Bool("help", false, "Help")
	help3 := flag.Bool("hh", false, "Help")

	flag.Parse()

	if *help || *help2 || *help3 {
		printHelp()
		os.Exit(0)
	}

	if cfg.Domain == "" {
		printHelp()
		os.Exit(1)
	}

	return &cfg
}

func runCommand(cmdStr string, cfg *Config) {
	if cfg.Verbose {
		fmt.Println("[RUNNING] ", cmdStr)
	}
	cmd := exec.Command("bash", "-c", cmdStr)
	if err := cmd.Run(); err != nil {
		logError(fmt.Sprintf("Command failed: %s | Error: %v", cmdStr, err))
	}
}

func reconDomain(cfg *Config) {
	fmt.Println("Starting recon for:", cfg.Domain)
	dir := filepath.Join(cfg.Output, cfg.Domain)
	os.MkdirAll(dir, os.ModePerm)

	var wg sync.WaitGroup

	// parallel recon tools
	tools := []string{
		fmt.Sprintf("subfinder -d %s -all --recursive -o %s/subfinder.txt", cfg.Domain, dir),
		fmt.Sprintf("amass enum -passive -d %s -o %s/amass.txt -v", cfg.Domain, dir),
		fmt.Sprintf("assetfinder --subs-only %s | tee %s/assetfinder.txt", cfg.Domain, dir),
		fmt.Sprintf("findomain -t %s -u %s/findomain.txt", cfg.Domain, dir),
		fmt.Sprintf("python3 ~/black1hp/Sublist3r/sublist3r.py -d %s -o %s/sublist3r.txt", cfg.Domain, dir),
		fmt.Sprintf(`curl -s "https://crt.sh/?q=%%25.%s&output=json" | jq -r '.[].name_value' | sed 's/\\*/\n/g' | sort -u > %s/crt.txt`, cfg.Domain, dir),
		fmt.Sprintf("python3 ~/black1hp/dnscan/dnscan.py -d %s -w %s -t %d | tee %s/bruteforce-dnscan.txt", cfg.Domain, cfg.Wordlist, cfg.Threads, dir),
		fmt.Sprintf(`ffuf -H "Host: FUZZ.%s" -u https://%s/ -w %s -mc 200,302 -o %s/vhosts.json`, cfg.Domain, cfg.Domain, cfg.Wordlist, dir),
	}

	for _, c := range tools {
		wg.Add(1)
		go func(cmd string) {
			defer wg.Done()
			runCommand(cmd, cfg)
		}(c)
	}
	wg.Wait()

	// Sequential post-processing
	sequential := []string{
		fmt.Sprintf(`grep -vE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+ ' %s/bruteforce-dnscan.txt > %s/bruteforce_subs.txt`, dir, dir),
		fmt.Sprintf(`jq -r '.results[].host' %s/vhosts.json | sort -u > %s/vhosts.hosts`, dir, dir),
		fmt.Sprintf(`cat %s/*.txt %s/*.hosts %s/bruteforce_subs.txt | sort -u > %s/all_subs.txt`, dir, dir, dir, dir),
		fmt.Sprintf(`dnsgen %s/all_subs.txt -w %s | sort -u > %s/permuted_subs.txt`, dir, cfg.Wordlist, dir),
		fmt.Sprintf(`dnsx -l %s/permuted_subs.txt -resp -o %s/resolved_subs.txt`, dir, dir),
		fmt.Sprintf(`awk '{print $1}' %s/resolved_subs.txt > %s/resolved_domains.txt`, dir, dir),
		fmt.Sprintf(`wc -l %s/all_subs.txt`, dir),
	}

	for _, c := range sequential {
		runCommand(c, cfg)
	}

	fmt.Println("Recon completed. Results saved in", dir)
	if stat, _ := os.Stat("Error.log"); stat.Size() > 0 {
		fmt.Println("⚠️  Some errors occurred. Check Error.log for details.")
	}
}

func main() {
	banner()
	initErrorLog()
	defer errorLog.Close()

	cfg := parseFlags()
	reconDomain(cfg)
}
