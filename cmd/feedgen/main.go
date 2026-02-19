// feedgen compiles YAML threat brief source files into an encrypted feed bundle.
//
// Usage:
//
//	feedgen -public-key <ed25519-hex> -briefs ./briefs -out ./output/bundle.json [-version <git-sha>]
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/craftedsignal/threat-feed/internal/compiler"
)

func main() {
	publicKey := flag.String("public-key", "", "Ed25519 public key (64 hex chars). Can also use PUBLIC_KEY env var.")
	briefsDir := flag.String("briefs", "briefs", "Directory containing YAML brief source files.")
	outFile := flag.String("out", "output/bundle.json", "Output path for the encrypted bundle.")
	version := flag.String("version", "", "Bundle version. Defaults to git commit SHA.")
	maxAgeDays := flag.Int("max-age-days", 0, "Exclude briefs older than N days (default: ~5 years). 0 uses the default.")
	flag.Parse()

	// Resolve public key (flag > env)
	key := *publicKey
	if key == "" {
		key = os.Getenv("PUBLIC_KEY")
	}
	if key == "" {
		fmt.Fprintln(os.Stderr, "error: Ed25519 public key required (-public-key flag or PUBLIC_KEY env var)")
		os.Exit(1)
	}

	// Resolve version from git if not provided
	ver := *version
	if ver == "" {
		ver = gitVersion()
	}

	fmt.Printf("feedgen: compiling briefs from %s\n", *briefsDir)

	// Load YAML briefs
	briefs, err := compiler.LoadBriefs(*briefsDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading briefs: %v\n", err)
		os.Exit(1)
	}
	if len(briefs) == 0 {
		fmt.Fprintln(os.Stderr, "error: no brief files found")
		os.Exit(1)
	}

	fmt.Printf("feedgen: loaded %d brief(s), %d total rules\n", len(briefs), countRules(briefs))

	// Compile to bundle format (exclude old briefs)
	maxAge := compiler.DefaultMaxBriefAge
	if *maxAgeDays > 0 {
		maxAge = time.Duration(*maxAgeDays) * 24 * time.Hour
	}
	content := compiler.Compile(briefs, maxAge)

	// Encrypt using derived key from public key
	publishedAt := time.Now().UTC().Format(time.RFC3339)
	manifest, err := compiler.Encrypt(content, ver, publishedAt, key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error encrypting bundle: %v\n", err)
		os.Exit(1)
	}

	// Write output
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error marshaling manifest: %v\n", err)
		os.Exit(1)
	}

	if err := os.MkdirAll("output", 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "error creating output directory: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(*outFile, data, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "error writing bundle: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("feedgen: bundle written to %s (version: %s, size: %d bytes)\n", *outFile, ver, len(data))
}

// gitVersion returns the short git commit SHA, or a fallback.
func gitVersion() string {
	out, err := exec.Command("git", "rev-parse", "--short", "HEAD").Output()
	if err != nil {
		return time.Now().UTC().Format("2006.01.02")
	}
	sha := strings.TrimSpace(string(out))
	// Prefix with date for human readability
	date := time.Now().UTC().Format("2006.01.02")
	return date + "." + sha
}

func countRules(briefs []compiler.Brief) int {
	n := 0
	for _, b := range briefs {
		n += len(b.Rules)
	}
	return n
}
