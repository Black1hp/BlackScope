// BlackScope — Subdomain Recon & Discovery Toolkit v2.1
// Author: Black1hp | github.com/black1hp
// Enhancements: AlterX integration, cleaner output, dual-pass dnsx

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

/* ---------------------------- configuration ---------------------------- */

type Config struct {
	Domain, Wordlist, Output string
	Threads                  int
	Verbose                  bool
}

var errorLog *os.File

/* ---------------------------- helpers ---------------------------- */

func initErrorLog() {
	var err error
	errorLog, err = os.OpenFile("Error.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		log.Fatalf("Failed to open Error.log: %v", err)
	}
}
func logError(msg string) { _, _ = errorLog.WriteString(msg + "\n") }

func banner() {
	fmt.Println(`
__________.__                 __      _________
\______   \  | _____    ____ |  | __ /   _____/ ____  ____ ______   ____
 |    |  _/  | \__  \ _/ ___\|  |/ / \_____  \_/ ___\/  _ \\____ \_/ __ \
 |    |   \  |__/ __ \\  \___|    <  /        \  \__(  <_> )  |_> >  ___/
 |______  /____(____  /\___  >__|_ \/_______  /\___  >____/|   __/ \___  >
        \/          \/     \/     \/        \/     \/      |__|        \/

        BlackScope — Subdomain Recon & Discovery Toolkit v2.1
        Author: Black1hp | github.com/black1hp
        AlterX permutations • dual-pass dnsx • clean output
`)
}

/* ---------------------------- flags ---------------------------- */

func parseFlags() *Config {
	var cfg Config
	flag.StringVar(&cfg.Domain, "d", "", "Target domain")
	flag.StringVar(&cfg.Domain, "domain", "", "Target domain")
	defWL := filepath.Join(os.Getenv("HOME"),
		"SecLists/Discovery/DNS/subdomains-top1million-110000.txt")
	flag.StringVar(&cfg.Wordlist, "w", defWL, "Wordlist path")
	flag.StringVar(&cfg.Wordlist, "wordlist", defWL, "Wordlist path")
	flag.StringVar(&cfg.Output, "o", "./results", "Output directory")
	flag.StringVar(&cfg.Output, "output", "./results", "Output directory")
	flag.IntVar(&cfg.Threads, "t", 300, "Threads")
	flag.IntVar(&cfg.Threads, "threads", 300, "Threads")
	flag.BoolVar(&cfg.Verbose, "v", false, "Verbose")
	flag.BoolVar(&cfg.Verbose, "verbose", false, "Verbose")

	showHelp := flag.Bool("h", false, "Help")
	flag.BoolVar(showHelp, "help", false, "Help")
	flag.BoolVar(showHelp, "hh", false, "Help")
	flag.Parse()

	if *showHelp || cfg.Domain == "" {
		fmt.Println("Usage: go run BlackScope.go -d target.com [options]")
		os.Exit(0)
	}
	return &cfg
}

func run(cmd string, v bool) {
	if v {
		fmt.Println("🔍", cmd)
	}
	if err := exec.Command("bash", "-c", cmd).Run(); err != nil {
		logError(fmt.Sprintf("cmd failed: %s | %v", cmd, err))
	}
}

/* ------------------------- cleaning routine ------------------------- */

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
		// strip leading "IP - " if present
		if idx := strings.Index(line, " - "); idx != -1 &&
			strings.Count(line[:idx], ".") == 3 &&
			line[0] >= '0' && line[0] <= '9' {
			line = strings.TrimSpace(line[idx+3:])
		}
		if !strings.HasSuffix(line, "."+domain) ||
			strings.Contains(line, " ") {
			continue
		}
		if _, ok := seen[line]; !ok {
			seen[line] = struct{}{}
			fmt.Fprintln(w, line)
		}
	}
	return sc.Err()
}

/* ----------------------------- recon ----------------------------- */

func recon(cfg *Config) {
	outDir := filepath.Join(cfg.Output, cfg.Domain)
	_ = os.MkdirAll(outDir, 0755)

	var wg sync.WaitGroup
	passive := []string{
		fmt.Sprintf("subfinder -silent -all -recursive -d %s -o %s/subfinder.txt", cfg.Domain, outDir),
		fmt.Sprintf("amass enum -passive -d %s -o %s/amass.txt", cfg.Domain, outDir),
		fmt.Sprintf("assetfinder --subs-only %s > %s/assetfinder.txt", cfg.Domain, outDir),
		fmt.Sprintf("findomain -t %s -u %s/findomain.txt", cfg.Domain, outDir),
		fmt.Sprintf(`curl -s "https://crt.sh/?q=%s&output=json" | jq -r '.[].name_value' | sed 's/\*\.\?//g' | sort -u > %s/crt.txt`,
			cfg.Domain, outDir),
	}
	for _, c := range passive {
		wg.Add(1)
		go func(cmd string) { defer wg.Done(); run(cmd, cfg.Verbose) }(c)
	}
	wg.Wait()

	// ffuf vhost
	run(fmt.Sprintf(`ffuf -s -H "Host: FUZZ.%s" -u https://%s/ -w %s -mc 200,301,302 -o %s/vhosts.json`,
		cfg.Domain, cfg.Domain, cfg.Wordlist, outDir), cfg.Verbose)

	// aggregate raw
	run(fmt.Sprintf(`find %[1]s -name "*.txt" -exec cat {} \; > %[1]s/all_raw.txt && \
	jq -r '.results[]?.host // empty' %[1]s/vhosts.json >> %[1]s/all_raw.txt`, outDir), cfg.Verbose)

	// clean
	if err := cleanSubdomainFile(filepath.Join(outDir, "all_raw.txt"),
		filepath.Join(outDir, "all_subs.txt"), cfg.Domain); err != nil {
		logError("cleaning error: " + err.Error())
	}

	/* -------- AlterX permutations -------- */
	alterx := "/root/go/bin/alterx"
	if _, err := exec.LookPath(alterx); err != nil {
		alterx = "alterx"
	}
	run(fmt.Sprintf(`%s -l %s/all_subs.txt -en -o %s/permuted_subs.txt`,
		alterx, outDir, outDir), cfg.Verbose)

	/* -------- dnsx dual pass -------- */
	run(fmt.Sprintf(`dnsx -silent -l %s/permuted_subs.txt -o %s/resolved_subs.txt`,
		outDir, outDir), cfg.Verbose) // domains only

	run(fmt.Sprintf(`dnsx -silent -ro -l %s/permuted_subs.txt -o %s/resolved_ips.txt`,
		outDir, outDir), cfg.Verbose) // ips only

	// merge results
	run(fmt.Sprintf(`cat %s/resolved_subs.txt >> %s/all_subs.txt && \
	sort -u %s/all_subs.txt -o %s/all_subs.txt`, outDir, outDir, outDir, outDir), cfg.Verbose)
	run(fmt.Sprintf(`cat %s/resolved_ips.txt %s/ip_list.txt 2>/dev/null | \
	sort -u > %s/ip_list.txt`, outDir, outDir, outDir), cfg.Verbose)

	run(fmt.Sprintf(`sed -i 's/^\([0-9]\{1,3\}\.\)\{3\}[0-9]\{1,3\} - //' %s/all_subs.txt`,
		outDir), cfg.Verbose)

	// stats
	fmt.Print("\n🗒  Final counts → ")
	run("wc -l "+filepath.Join(outDir, "all_subs.txt"), false)
}

/* ----------------------------- main ----------------------------- */

func main() {
	banner()
	initErrorLog()
	defer errorLog.Close()

	cfg := parseFlags()
	recon(cfg)
}
