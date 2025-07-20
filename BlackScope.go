// BlackScope — Subdomain Recon & Discovery Toolkit v3.2
// Author: Black1hp | github.com/black1hp
//
// Optimized Version: Single-pass DNSX w/JSON, efficient deduplication, modern post-processing
// Features: Bulk mode, per-command timing/debugging, full passive/active recon, AlterX, clean output

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
        "time"
)

type Config struct {
        Domain, DomainFile, Wordlist, Output string
        Threads, MaxConcurrent               int
        Verbose                              bool
}

var (
        errorLog *os.File
        debugLog *os.File
)

/* ---------------------------- Logging ---------------------------- */

func initLogs() {
        var err error
        errorLog, err = os.OpenFile("Error.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
        if err != nil {
                log.Fatalf("Failed to open Error.log: %v", err)
        }
        debugLog, err = os.OpenFile("debug.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
        if err != nil {
                log.Fatalf("Failed to open debug.log: %v", err)
        }
}

func logError(msg string) { _, _ = errorLog.WriteString(msg + "\n") }
func logDebug(msg string) { _, _ = debugLog.WriteString(msg + "\n") }

func banner() {
        fmt.Println(`
__________.__                 __      _________
\______   \  | _____    ____ |  | __ /   _____/ ____  ____ ______   ____
 |    |  _/  | \__  \ _/ ___\|  |/ / \_____  \_/ ___\/  _ \\____ \_/ __ \
 |    |   \  |__/ __ \\  \___|    <  /        \  \__(  <_> )  |_> >  ___/
 |______  /____(____  /\___  >__|_ \/_______  /\___  >____/|   __/ \___  >
        \/          \/     \/     \/        \/     \/      |__|        \/

            BlackScope — Subdomain Recon & Discovery Toolkit v3.2
            Author: Black1hp | github.com/black1hp
            Optimized: Single-pass DNSX, dedup-first approach
`)
}

func printHelp() {
        fmt.Println(`
Usage:
  Single domain:  go run BlackScope.go -d target.com [options]
  Bulk domains:   go run BlackScope.go -f domains.txt [options]

Options:
  -d, --domain      Target domain (single domain mode)
  -f, --file        File containing list of domains (bulk mode)
  -w, --wordlist    Wordlist path (default: ~/SecLists/Discovery/DNS/subdomains-top1million-110000.txt)
  -t, --threads     Number of threads per domain (default: 300)
  -c, --concurrent  Max concurrent domains to process (default: 3)
  -o, --output      Output directory (default: ./results)
  -v, --verbose     Enable verbose output
  -h, --help        Show this help page

Examples:
  go run BlackScope.go -d bitmovin.com -v
  go run BlackScope.go -f domains.txt -c 5 -v
`)
}

/* ---------------------------- Flags ---------------------------- */

func parseFlags() *Config {
        var cfg Config
        flag.StringVar(&cfg.Domain, "d", "", "Target domain")
        flag.StringVar(&cfg.Domain, "domain", "", "Target domain")
        flag.StringVar(&cfg.DomainFile, "f", "", "File containing domains")
        flag.StringVar(&cfg.DomainFile, "file", "", "File containing domains")
        defWL := filepath.Join(os.Getenv("HOME"), "SecLists/Discovery/DNS/subdomains-top1million-110000.txt")
        flag.StringVar(&cfg.Wordlist, "w", defWL, "Wordlist path")
        flag.StringVar(&cfg.Wordlist, "wordlist", defWL, "Wordlist path")
        flag.StringVar(&cfg.Output, "o", "./results", "Output directory")
        flag.StringVar(&cfg.Output, "output", "./results", "Output directory")
        flag.IntVar(&cfg.Threads, "t", 300, "Threads per domain")
        flag.IntVar(&cfg.Threads, "threads", 300, "Threads per domain")
        flag.IntVar(&cfg.MaxConcurrent, "c", 3, "Max concurrent domains")
        flag.IntVar(&cfg.MaxConcurrent, "concurrent", 3, "Max concurrent domains")
        flag.BoolVar(&cfg.Verbose, "v", false, "Verbose")
        flag.BoolVar(&cfg.Verbose, "verbose", false, "Verbose")
        showHelp := flag.Bool("h", false, "Help")
        flag.BoolVar(showHelp, "help", false, "Help")
        flag.BoolVar(showHelp, "hh", false, "Help")
        flag.Parse()

        if *showHelp {
                printHelp()
                os.Exit(0)
        }
        if cfg.Domain == "" && cfg.DomainFile == "" {
                fmt.Println("❌ Error: Either -d (domain) or -f (file) is required!")
                printHelp()
                os.Exit(1)
        }
        if cfg.Domain != "" && cfg.DomainFile != "" {
                fmt.Println("❌ Error: Cannot use both -d and -f flags simultaneously!")
                printHelp()
                os.Exit(1)
        }
        return &cfg
}

/* ------------------------ Domain File Loader ------------------------ */

func readDomainsFromFile(filename string) ([]string, error) {
        file, err := os.Open(filename)
        if err != nil {
                return nil, fmt.Errorf("failed to open domain file: %v", err)
        }
        defer file.Close()
        var domains []string
        scanner := bufio.NewScanner(file)
        lineNum := 0
        for scanner.Scan() {
                lineNum++
                line := strings.TrimSpace(scanner.Text())
                if line == "" || strings.HasPrefix(line, "#") {
                        continue
                }
                if !strings.Contains(line, ".") {
                        fmt.Printf("⚠️  Warning: Line %d appears invalid: %s\n", lineNum, line)
                        continue
                }
                domains = append(domains, line)
        }
        if err := scanner.Err(); err != nil {
                return nil, fmt.Errorf("error reading file: %v", err)
        }
        if len(domains) == 0 {
                return nil, fmt.Errorf("no valid domains found in file")
        }
        return domains, nil
}

/* ------------------------ Helpers and Exec ------------------------ */

func runCommand(cmd string, v bool, domain string) {
        if v {
                fmt.Printf("[START][%s] %s\n", domain, cmd)
        }
        start := time.Now()
        command := exec.Command("bash", "-c", cmd)
        err := command.Run()
        elapsed := time.Since(start)
        debugMsg := fmt.Sprintf("[END][%s] %s (Duration: %s)\n", domain, cmd, elapsed)
        logDebug(debugMsg)
        if v {
                fmt.Print(debugMsg)
        }
        if err != nil {
                logError(fmt.Sprintf("Command failed: %s | Error: %v", cmd, err))
        }
}

// Cleans and dedups found subs for a given domain
func cleanSubdomainFile(in, out, domain string) error {
        r, err := os.Open(in)
        if err != nil {
                return err
        }
        defer r.Close()
        w, err := os.Create(out)
        if err != nil {
                return err
        }
        defer w.Close()
        seen := make(map[string]struct{})
        sc := bufio.NewScanner(r)
        for sc.Scan() {
                line := strings.TrimSpace(sc.Text())
                if line == "" || strings.HasPrefix(line, "#") {
                        continue
                }
                if idx := strings.Index(line, " - "); idx != -1 &&
                        strings.Count(line[:idx], ".") == 3 &&
                        line[0] >= '0' && line[0] <= '9' {
                        line = strings.TrimSpace(line[idx+3:])
                }
                if !strings.HasSuffix(line, "."+domain) || strings.Contains(line, " ") {
                        continue
                }
                if _, ok := seen[line]; !ok {
                        seen[line] = struct{}{}
                        fmt.Fprintln(w, line)
                }
        }
        return sc.Err()
}

/* ---------------------------- Core Recon ---------------------------- */

func reconSingleDomain(domain string, cfg *Config) (int, error) {
        if cfg.Verbose {
                fmt.Printf("\n🎯 Processing domain: %s\n", domain)
        }
        outDir := filepath.Join(cfg.Output, domain)
        if err := os.MkdirAll(outDir, 0755); err != nil {
                return 0, fmt.Errorf("failed to create output directory: %v", err)
        }
        var wg sync.WaitGroup
        passive := []string{
                fmt.Sprintf("subfinder -silent -all -recursive -d %s -o %s/subfinder.txt", domain, outDir),
                fmt.Sprintf("amass enum -passive -d %s -o %s/amass.txt", domain, outDir),
                fmt.Sprintf("assetfinder --subs-only %s > %s/assetfinder.txt", domain, outDir),
                fmt.Sprintf("findomain -t %s -u %s/findomain.txt", domain, outDir),
                fmt.Sprintf(`curl -s "https://crt.sh/?q=%s&output=json" | jq -r '.[].name_value' | sed 's/\*\.\?//g' | sort -u > %s/crt.txt`,
                        domain, outDir),
        }
        for _, c := range passive {
                wg.Add(1)
                go func(cmd string) {
                        defer wg.Done()
                        runCommand(cmd, cfg.Verbose, domain)
                }(c)
        }
        wg.Wait()

        // FFUF virtual host brute
        runCommand(fmt.Sprintf(
                `ffuf -s -H "Host: FUZZ.%s" -u https://%s/ -w %s -mc 200,301,302 -o %s/vhosts.json`,
                domain, domain, cfg.Wordlist, outDir), cfg.Verbose, domain)
        runCommand(fmt.Sprintf(
                `find %[1]s -name "*.txt" -exec cat {} \; > %[1]s/all_raw.txt && jq -r '.results[]?.host // empty' %[1]s/vhosts.json >> %[1]s/all_raw.txt 2>/dev/null || true`,
                outDir), cfg.Verbose, domain)

        // Clean + dedup to all_subs.txt
        if err := cleanSubdomainFile(filepath.Join(outDir, "all_raw.txt"),
                filepath.Join(outDir, "all_subs.txt"), domain); err != nil {
                logError("cleaning error: " + err.Error())
        }
        runCommand(fmt.Sprintf(`sort -u %s/all_subs.txt -o %s/all_subs.txt`, outDir, outDir), cfg.Verbose, domain)

        // Permute -- then dedup permuted subs
        alterx := "/root/go/bin/alterx"
        if _, err := exec.LookPath(alterx); err != nil {
                alterx = "alterx"
        }
        runCommand(fmt.Sprintf(`%s -l %s/all_subs.txt -en -o %s/permuted_subs.txt 2>/dev/null || echo "AlterX failed" > %s/alterx_error.log`,
                alterx, outDir, outDir, outDir), cfg.Verbose, domain)
        runCommand(fmt.Sprintf(`sort -u %s/permuted_subs.txt -o %s/permuted_subs.txt`, outDir, outDir), cfg.Verbose, domain)

        // 🚀 SINGLE JSON DNSX RUN
        runCommand(fmt.Sprintf(
                `dnsx -silent -json -l %s/permuted_subs.txt -o %s/resolved_dnsx.json 2>/dev/null || true`,
                outDir, outDir), cfg.Verbose, domain)

        // Extract all resolved subdomains and IPs using jq
        runCommand(fmt.Sprintf(
                `jq -r '.host' %s/resolved_dnsx.json | sort -u > %s/resolved_subs.txt`, outDir, outDir), cfg.Verbose, domain)
        runCommand(fmt.Sprintf(
                `jq -r '.a[]?' %s/resolved_dnsx.json | sort -u > %s/ip_list.txt`, outDir, outDir), cfg.Verbose, domain)

        // Combine, dedup for reporting
        runCommand(fmt.Sprintf(
                `cat %s/resolved_subs.txt >> %s/all_subs.txt && sort -u %s/all_subs.txt -o %s/all_subs.txt`,
                outDir, outDir, outDir, outDir), cfg.Verbose, domain)

        // Output stats
        allSubsFile := filepath.Join(outDir, "all_subs.txt")
        count := 0
        if file, err := os.Open(allSubsFile); err == nil {
                scanner := bufio.NewScanner(file)
                for scanner.Scan() {
                        if strings.TrimSpace(scanner.Text()) != "" {
                                count++
                        }
                }
                file.Close()
        }
        if cfg.Verbose {
                fmt.Printf("✅ %s completed: %d subdomains found\n", domain, count)
        }
        return count, nil
}

/* ---------------------- Bulk Processing ---------------------- */

type DomainResult struct {
        Domain string
        Count  int
        Error  error
}

func processDomainsConcurrently(domains []string, cfg *Config) {
        fmt.Printf("🚀 Starting bulk processing of %d domains (max %d concurrent)\n", len(domains), cfg.MaxConcurrent)
        semaphore := make(chan struct{}, cfg.MaxConcurrent)
        results := make(chan DomainResult, len(domains))
        var wg sync.WaitGroup
        for _, domain := range domains {
                wg.Add(1)
                go func(d string) {
                        defer wg.Done()
                        semaphore <- struct{}{}
                        defer func() { <-semaphore }()
                        count, err := reconSingleDomain(d, cfg)
                        results <- DomainResult{Domain: d, Count: count, Error: err}
                }(domain)
        }
        go func() {
                wg.Wait()
                close(results)
        }()
        var successful, failed, totalSubdomains int
        var failedDomains []string
        fmt.Println("\n📊 Processing Results:")
        fmt.Println(strings.Repeat("=", 50))
        for result := range results {
                if result.Error != nil {
                        failed++
                        failedDomains = append(failedDomains, result.Domain)
                        fmt.Printf("❌ %-20s | Error: %v\n", result.Domain, result.Error)
                } else {
                        successful++
                        totalSubdomains += result.Count
                        fmt.Printf("✅ %-20s | %d subdomains\n", result.Domain, result.Count)
                }
        }
        generateSummary(cfg.Output, domains, successful, failed, totalSubdomains, failedDomains)
}

func generateSummary(outputDir string, domains []string, successful, failed, totalSubdomains int, failedDomains []string) {
        summaryFile := filepath.Join(outputDir, "summary.txt")
        file, err := os.Create(summaryFile)
        if err != nil {
                logError(fmt.Sprintf("Failed to create summary file: %v", err))
                return
        }
        defer file.Close()
        fmt.Fprintf(file, "BlackScope v3.2 - Bulk Processing Summary\n")
        fmt.Fprintf(file, "========================================\n\n")
        fmt.Fprintf(file, "Total domains processed: %d\n", len(domains))
        fmt.Fprintf(file, "Successful: %d\n", successful)
        fmt.Fprintf(file, "Failed: %d\n", failed)
        fmt.Fprintf(file, "Total subdomains found: %d\n", totalSubdomains)
        fmt.Fprintf(file, "Average per domain: %.1f\n\n", float64(totalSubdomains)/float64(successful))
        if len(failedDomains) > 0 {
                fmt.Fprintf(file, "Failed domains:\n")
                for _, domain := range failedDomains {
                        fmt.Fprintf(file, "- %s\n", domain)
                }
        }
        fmt.Printf("\n📋 Summary:\n")
        fmt.Printf("   Total domains: %d\n", len(domains))
        fmt.Printf("   Successful: %d\n", successful)
        fmt.Printf("   Failed: %d\n", failed)
        fmt.Printf("   Total subdomains: %d\n", totalSubdomains)
        fmt.Printf("   Summary saved: %s\n", summaryFile)
}

/* --------------------------- Main ---------------------------- */

func main() {
        banner()
        initLogs()
        defer errorLog.Close()
        defer debugLog.Close()
        cfg := parseFlags()
        if err := os.MkdirAll(cfg.Output, 0755); err != nil {
                log.Fatalf("Failed to create output directory: %v", err)
        }
        if cfg.DomainFile != "" {
                domains, err := readDomainsFromFile(cfg.DomainFile)
                if err != nil {
                        log.Fatalf("❌ Failed to read domain file: %v", err)
                }
                fmt.Printf("📁 Loaded %d domains from %s\n", len(domains), cfg.DomainFile)
                processDomainsConcurrently(domains, cfg)
        } else {
                fmt.Printf("🎯 Single domain mode: %s\n", cfg.Domain)
                count, err := reconSingleDomain(cfg.Domain, cfg)
                if err != nil {
                        log.Fatalf("❌ Failed to process domain: %v", err)
                }
                fmt.Printf("✅ Completed: %d subdomains found\n", count)
        }
        fmt.Println("\n🎉 BlackScope execution completed!")
}
