package main

import (
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

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
	baseRef := flags.String("base-ref", "", "compare changed briefs with their version at this Git revision")
	previousPaths := make(previousPathFlag)
	flags.Var(previousPaths, "previous-path", "rename mapping in CURRENT=PREVIOUS form; may be repeated")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *baseRef != "" {
		if err := exec.Command("git", "cat-file", "-e", *baseRef+"^{commit}").Run(); err != nil {
			fmt.Fprintf(os.Stderr, "feedcheck: base-ref %q is not an available commit\n", *baseRef)
			return 2
		}
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
			if *baseRef != "" {
				previousPath := path
				if mapped, ok := previousPaths[path]; ok {
					previousPath = mapped
				}
				previous, exists, err := readGitFile(*baseRef, previousPath)
				if err != nil {
					issues = append(issues, publicfeed.Issue{Path: path, Code: "git.read", Severity: publicfeed.SeverityError, Message: err.Error()})
				} else if exists {
					issues = append(issues, publicfeed.CheckBriefAppendOnly(path, previous, data)...)
				}
			}
		case strings.HasSuffix(path, "sitemap.xml"):
			for _, item := range publicfeed.CheckSitemap(data) {
				item.Path = path
				issues = append(issues, item)
			}
		case strings.HasSuffix(path, ".json") && isSTIXPath(path):
			if filepath.Base(path) == "index.json" {
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

type previousPathFlag map[string]string

func (values previousPathFlag) String() string { return "" }

func (values previousPathFlag) Set(value string) error {
	current, previous, ok := strings.Cut(value, "=")
	if !ok || current == "" || previous == "" {
		return fmt.Errorf("previous-path must use CURRENT=PREVIOUS")
	}
	values[current] = previous
	return nil
}

func readGitFile(ref, path string) ([]byte, bool, error) {
	object := ref + ":" + filepath.ToSlash(path)
	probe := exec.Command("git", "cat-file", "-e", object)
	if err := probe.Run(); err != nil {
		if _, ok := err.(*exec.ExitError); ok {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("checking previous %s: %w", path, err)
	}
	data, err := exec.Command("git", "show", object).Output()
	if err != nil {
		return nil, false, fmt.Errorf("reading previous %s: %w", path, err)
	}
	return data, true, nil
}

func isSTIXPath(path string) bool {
	clean := filepath.ToSlash(path)
	return strings.Contains(clean, "/stix/") || strings.HasSuffix(clean, "/stix.json")
}

type manifest struct {
	Version     string          `json:"version"`
	SpecVersion string          `json:"spec_version"`
	Generated   string          `json:"generated"`
	Description string          `json:"description"`
	Rolling     manifestEntry   `json:"rolling"`
	Months      []manifestEntry `json:"months"`
}

type manifestEntry struct {
	Month          string `json:"month,omitempty"`
	Path           string `json:"path"`
	Checksum       string `json:"checksum"`
	SizeBytes      int64  `json:"size_bytes"`
	ReportCount    int    `json:"report_count"`
	FirstPublished string `json:"first_published,omitempty"`
	LastPublished  string `json:"last_published,omitempty"`
	Generated      string `json:"generated"`
	SpecVersion    string `json:"spec_version"`
}

var (
	manifestChecksumPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	manifestMonthPattern    = regexp.MustCompile(`^[0-9]{4}-(0[1-9]|1[0-2])$`)
	manifestRollingPath     = regexp.MustCompile(`^/stix/releases/sha256-([0-9a-f]{64})\.json$`)
	manifestMonthPath       = regexp.MustCompile(`^/stix/releases/([0-9]{4}-(?:0[1-9]|1[0-2]))-sha256-([0-9a-f]{64})\.json$`)
)

func checkManifest(path string, data []byte) []publicfeed.Issue {
	var rawTop map[string]json.RawMessage
	if err := json.Unmarshal(data, &rawTop); err != nil {
		return []publicfeed.Issue{manifestIssue(path, "json", "stix.manifest_json", err.Error())}
	}
	var index manifest
	if err := json.Unmarshal(data, &index); err != nil {
		return []publicfeed.Issue{manifestIssue(path, "json", "stix.manifest_json", err.Error())}
	}
	var issues []publicfeed.Issue
	issues = append(issues, checkManifestTop(path, rawTop, index)...)

	var rollingRaw map[string]json.RawMessage
	if raw := rawTop["rolling"]; raw != nil {
		_ = json.Unmarshal(raw, &rollingRaw)
	}
	var monthsRaw []map[string]json.RawMessage
	if raw := rawTop["months"]; raw != nil {
		_ = json.Unmarshal(raw, &monthsRaw)
	}

	type indexedEntry struct {
		entry     manifestEntry
		raw       map[string]json.RawMessage
		field     string
		isRolling bool
	}
	entries := []indexedEntry{{entry: index.Rolling, raw: rollingRaw, field: "rolling", isRolling: true}}
	for i, entry := range index.Months {
		var raw map[string]json.RawMessage
		if i < len(monthsRaw) {
			raw = monthsRaw[i]
		}
		entries = append(entries, indexedEntry{entry: entry, raw: raw, field: fmt.Sprintf("months[%d]", i)})
	}

	seenPaths := make(map[string]bool)
	seenMonths := make(map[string]bool)
	staticRoot := filepath.Dir(filepath.Dir(path))
	for _, indexed := range entries {
		entry := indexed.entry
		issues = append(issues, checkManifestEntry(path, indexed.field, indexed.raw, entry, indexed.isRolling)...)
		if entry.Path == "" || !strings.HasPrefix(entry.Path, "/") || strings.Contains(entry.Path, "..") {
			continue
		}
		if seenPaths[entry.Path] {
			issues = append(issues, manifestIssue(path, indexed.field+".path", "stix.manifest_contract", "manifest paths must be unique"))
		}
		seenPaths[entry.Path] = true
		if !indexed.isRolling {
			if seenMonths[entry.Month] {
				issues = append(issues, manifestIssue(path, indexed.field+".month", "stix.manifest_contract", "manifest months must be unique"))
			}
			seenMonths[entry.Month] = true
		}

		bundlePath := filepath.Join(staticRoot, filepath.FromSlash(strings.TrimPrefix(entry.Path, "/")))
		bundle, err := os.ReadFile(bundlePath)
		if err != nil {
			issues = append(issues, manifestIssue(bundlePath, "", "file.read", err.Error()))
			continue
		}
		actualChecksum := sha256.Sum256(bundle)
		if entry.Checksum != fmt.Sprintf("sha256:%x", actualChecksum) {
			issues = append(issues, manifestIssue(path, indexed.field+".checksum", "stix.manifest_checksum", "checksum does not match the referenced bundle"))
		}
		if entry.SizeBytes != int64(len(bundle)) {
			issues = append(issues, manifestIssue(path, indexed.field+".size_bytes", "stix.manifest_size", fmt.Sprintf("manifest declares %d bytes, bundle has %d", entry.SizeBytes, len(bundle))))
		}
		issues = append(issues, publicfeed.CheckSTIXWithReportCount(bundlePath, bundle, entry.ReportCount)...)
		issues = append(issues, checkManifestBounds(path, indexed.field, entry, bundle, indexed.isRolling)...)
	}
	sort.SliceStable(issues, func(i, j int) bool {
		if issues[i].Path != issues[j].Path {
			return issues[i].Path < issues[j].Path
		}
		if issues[i].Field != issues[j].Field {
			return issues[i].Field < issues[j].Field
		}
		return issues[i].Code < issues[j].Code
	})
	return issues
}

func manifestIssue(path, field, code, message string) publicfeed.Issue {
	return publicfeed.Issue{Path: path, Field: field, Code: code, Severity: publicfeed.SeverityError, Message: message}
}

func checkManifestTop(path string, raw map[string]json.RawMessage, index manifest) []publicfeed.Issue {
	allowed := map[string]bool{
		"version": true, "spec_version": true, "generated": true,
		"description": true, "rolling": true, "months": true,
	}
	var issues []publicfeed.Issue
	for key := range raw {
		if !allowed[key] {
			issues = append(issues, manifestIssue(path, key, "stix.manifest_fields", "unknown top-level manifest field"))
		}
	}
	for key := range allowed {
		if _, exists := raw[key]; !exists {
			issues = append(issues, manifestIssue(path, key, "stix.manifest_contract", "required top-level manifest field is missing"))
		}
	}
	if index.Version != "2.0" || index.SpecVersion != "2.1" || strings.TrimSpace(index.Description) == "" || !validManifestTime(index.Generated) {
		issues = append(issues, manifestIssue(path, "version/spec_version/generated/description", "stix.manifest_contract", "manifest requires version 2.0, spec_version 2.1, an RFC3339 generated time, and a description"))
	}
	if len(index.Months) == 0 {
		issues = append(issues, manifestIssue(path, "months", "stix.manifest_contract", "manifest months must not be empty"))
	}
	return issues
}

func checkManifestEntry(path, field string, raw map[string]json.RawMessage, entry manifestEntry, isRolling bool) []publicfeed.Issue {
	allowed := map[string]bool{
		"path": true, "checksum": true, "size_bytes": true, "report_count": true,
		"first_published": true, "last_published": true, "generated": true, "spec_version": true,
	}
	if !isRolling {
		allowed["month"] = true
	}
	var issues []publicfeed.Issue
	for key := range raw {
		if !allowed[key] {
			issues = append(issues, manifestIssue(path, field+"."+key, "stix.manifest_fields", "unknown manifest entry field"))
		}
	}
	required := []string{"path", "checksum", "size_bytes", "report_count", "generated", "spec_version"}
	if !isRolling {
		required = append(required, "month", "first_published", "last_published")
	} else if entry.ReportCount > 0 {
		required = append(required, "first_published", "last_published")
	}
	for _, key := range required {
		if _, exists := raw[key]; !exists {
			issues = append(issues, manifestIssue(path, field+"."+key, "stix.manifest_contract", "required manifest entry field is missing"))
		}
	}
	if isRolling && entry.ReportCount == 0 {
		if _, exists := raw["first_published"]; exists {
			issues = append(issues, manifestIssue(path, field+".first_published", "stix.manifest_contract", "zero-report rolling bounds must be omitted"))
		}
		if _, exists := raw["last_published"]; exists {
			issues = append(issues, manifestIssue(path, field+".last_published", "stix.manifest_contract", "zero-report rolling bounds must be omitted"))
		}
	}
	if entry.Path == "" || !strings.HasPrefix(entry.Path, "/") || strings.Contains(entry.Path, "..") || entry.SizeBytes < 1 || entry.ReportCount < 0 || entry.SpecVersion != "2.1" || !validManifestTime(entry.Generated) {
		issues = append(issues, manifestIssue(path, field, "stix.manifest_contract", "manifest entry has an invalid path, size, count, generated time, or spec version"))
	}
	if isRolling {
		match := manifestRollingPath.FindStringSubmatch(entry.Path)
		if match == nil {
			issues = append(issues, manifestIssue(path, field+".path", "stix.manifest_contract", "rolling path must identify an immutable content-addressed release"))
		} else if entry.Checksum != "sha256:"+match[1] {
			issues = append(issues, manifestIssue(path, field+".path", "stix.manifest_checksum", "release path digest must match checksum"))
		}
	} else {
		match := manifestMonthPath.FindStringSubmatch(entry.Path)
		if !manifestMonthPattern.MatchString(entry.Month) || match == nil || match[1] != entry.Month || entry.ReportCount < 1 {
			issues = append(issues, manifestIssue(path, field, "stix.manifest_contract", "monthly entry requires a YYYY-MM month, matching immutable release path, and at least one report"))
		} else if entry.Checksum != "sha256:"+match[2] {
			issues = append(issues, manifestIssue(path, field+".path", "stix.manifest_checksum", "release path digest must match checksum"))
		}
	}
	if !manifestChecksumPattern.MatchString(entry.Checksum) {
		issues = append(issues, manifestIssue(path, field+".checksum", "stix.manifest_checksum", "checksum must be sha256:<64 lowercase hex>"))
	}
	return issues
}

func checkManifestBounds(path, field string, entry manifestEntry, data []byte, isRolling bool) []publicfeed.Issue {
	type bundleObject struct {
		Type      string `json:"type"`
		Published string `json:"published"`
	}
	var bundle struct {
		Objects []bundleObject `json:"objects"`
	}
	if err := json.Unmarshal(data, &bundle); err != nil {
		return nil
	}
	var first, last time.Time
	count := 0
	for _, object := range bundle.Objects {
		if object.Type != "report" {
			continue
		}
		published, err := time.Parse(time.RFC3339Nano, object.Published)
		if err != nil {
			continue
		}
		if count == 0 || published.Before(first) {
			first = published
		}
		if count == 0 || published.After(last) {
			last = published
		}
		count++
	}
	if isRolling && count == 0 {
		return nil
	}
	declaredFirst, firstErr := time.Parse(time.RFC3339, entry.FirstPublished)
	declaredLast, lastErr := time.Parse(time.RFC3339, entry.LastPublished)
	if firstErr != nil || lastErr != nil || !declaredFirst.Equal(first) || !declaredLast.Equal(last) {
		return []publicfeed.Issue{manifestIssue(path, field+".first_published/last_published", "stix.manifest_bounds", "publication bounds must match the referenced reports")}
	}
	return nil
}

func validManifestTime(value string) bool {
	_, err := time.Parse(time.RFC3339, value)
	return err == nil
}
