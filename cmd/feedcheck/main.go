package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/craftedsignal/threat-feed/internal/publicfeed"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	flags := flag.NewFlagSet("feedcheck", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	generatedSite := flags.String("generated-site", "", "validate generated sitemap.xml below this directory")
	legacy := flags.Bool("legacy", false, "allow briefs that predate append-only metadata")
	if err := flags.Parse(args); err != nil {
		return 2
	}

	paths := append([]string(nil), flags.Args()...)
	if *generatedSite != "" {
		paths = append(paths, filepath.Join(*generatedSite, "sitemap.xml"))
	}
	if len(paths) == 0 {
		fmt.Fprintln(os.Stderr, "feedcheck: provide changed artifact paths or --generated-site DIR")
		return 2
	}
	sort.Strings(paths)

	var issues []publicfeed.Issue
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			issues = append(issues, publicfeed.Issue{Path: path, Code: "file.read", Severity: publicfeed.SeverityError, Message: err.Error()})
			continue
		}
		switch {
		case strings.HasSuffix(path, ".md"):
			mode := publicfeed.ModeStrict
			if *legacy {
				mode = publicfeed.ModeLegacy
			}
			issues = append(issues, publicfeed.CheckBriefWithMode(path, data, mode)...)
		case strings.HasSuffix(path, "sitemap.xml"):
			for _, item := range publicfeed.CheckSitemap(data) {
				item.Path = path
				issues = append(issues, item)
			}
		case strings.HasSuffix(path, ".json") && strings.Contains(filepath.ToSlash(path), "/stix/"):
			if strings.HasSuffix(path, "/index.json") {
				manifestIssues := checkManifest(path, data)
				issues = append(issues, manifestIssues...)
			} else {
				issues = append(issues, publicfeed.CheckSTIX(path, data)...)
			}
		default:
			issues = append(issues, publicfeed.Issue{Path: path, Code: "file.unsupported", Severity: publicfeed.SeverityError, Message: "unsupported public artifact type"})
		}
	}

	for _, item := range issues {
		field := ""
		if item.Field != "" {
			field = ":" + item.Field
		}
		fmt.Fprintf(os.Stderr, "%s%s: %s: %s\n", item.Path, field, item.Code, item.Message)
	}
	if len(issues) > 0 {
		return 1
	}
	fmt.Fprintf(os.Stdout, "feedcheck: validated %d artifact(s)\n", len(paths))
	return 0
}

type manifest struct {
	Months  []manifestEntry `json:"months"`
	Rolling manifestEntry   `json:"rolling"`
}

type manifestEntry struct {
	Path        string `json:"path"`
	ReportCount int    `json:"report_count"`
}

func checkManifest(path string, data []byte) []publicfeed.Issue {
	var index manifest
	if err := json.Unmarshal(data, &index); err != nil {
		return []publicfeed.Issue{{Path: path, Code: "stix.manifest_json", Severity: publicfeed.SeverityError, Message: err.Error()}}
	}
	entries := append([]manifestEntry{index.Rolling}, index.Months...)
	var issues []publicfeed.Issue
	for _, entry := range entries {
		if entry.Path == "" {
			continue
		}
		bundlePath := filepath.Join(filepath.Dir(path), filepath.Base(entry.Path))
		bundle, err := os.ReadFile(bundlePath)
		if err != nil {
			issues = append(issues, publicfeed.Issue{Path: bundlePath, Code: "file.read", Severity: publicfeed.SeverityError, Message: err.Error()})
			continue
		}
		issues = append(issues, publicfeed.CheckSTIXWithReportCount(bundlePath, bundle, entry.ReportCount)...)
	}
	return issues
}
