// Package publicfeed validates the public Markdown, STIX, and discovery
// artifacts produced by the threat intelligence publishing pipeline.
package publicfeed

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/url"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/craftedsignal/threat-feed/pkg/mitre"
	"gopkg.in/yaml.v3"
)

// Mode controls whether append-only publication metadata is required.
type Mode int

const (
	ModeStrict Mode = iota
	ModeLegacy
)

// Severity is the validation issue severity.
type Severity string

const (
	SeverityError Severity = "error"
	SeverityWarn  Severity = "warning"
)

// Issue is a stable, human-readable validation result.
type Issue struct {
	Path     string   `json:"path"`
	Field    string   `json:"field,omitempty"`
	Code     string   `json:"code"`
	Severity Severity `json:"severity"`
	Message  string   `json:"message"`
}

func issue(path, field, code, message string) Issue {
	return Issue{Path: path, Field: field, Code: code, Severity: SeverityError, Message: message}
}

func sorted(issues []Issue) []Issue {
	sort.SliceStable(issues, func(i, j int) bool {
		a, b := issues[i], issues[j]
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		if a.Field != b.Field {
			return a.Field < b.Field
		}
		if a.Code != b.Code {
			return a.Code < b.Code
		}
		return a.Message < b.Message
	})
	return issues
}

type briefDocument struct {
	Title                string                 `yaml:"title"`
	Slug                 string                 `yaml:"slug"`
	BriefID              string                 `yaml:"brief_id"`
	EventID              string                 `yaml:"event_id"`
	Revision             int                    `yaml:"revision"`
	ActivityAt           string                 `yaml:"activity_at"`
	Date                 string                 `yaml:"date"`
	Type                 string                 `yaml:"type"`
	Exploited            bool                   `yaml:"exploited"`
	ExploitationEvidence exploitationEvidence   `yaml:"exploitation_evidence"`
	CVEs                 []briefCVE             `yaml:"cves"`
	TTPs                 []briefTTP             `yaml:"mitre_ttps"`
	References           []string               `yaml:"references"`
	RevisionHistory      []briefRevision        `yaml:"revision_history"`
	SourceAssessment     map[string]interface{} `yaml:"source_assessment"`
	QAStatus             map[string]interface{} `yaml:"qa_status"`
}

type exploitationEvidence struct {
	Status     string `yaml:"status"`
	SourceURL  string `yaml:"source_url"`
	ObservedAt string `yaml:"observed_at"`
	Confidence string `yaml:"confidence"`
}

type briefCVE struct {
	ID        string `yaml:"id"`
	KEVStatus string `yaml:"kev_status"`
}

type briefTTP struct {
	TacticID         string `yaml:"tactic_id"`
	TacticName       string `yaml:"tactic_name"`
	TechniqueID      string `yaml:"technique_id"`
	TechniqueName    string `yaml:"technique_name"`
	SubtechniqueID   string `yaml:"subtechnique_id"`
	SubtechniqueName string `yaml:"subtechnique_name"`
}

type briefRevision struct {
	Revision      int      `yaml:"revision"`
	At            string   `yaml:"at"`
	Checksum      string   `yaml:"checksum"`
	Summary       string   `yaml:"summary"`
	ChangedFields []string `yaml:"changed_fields"`
	SourceURLs    []string `yaml:"source_urls"`
}

var (
	frontMatterDelimiter = []byte("---")
	cvePattern           = regexp.MustCompile(`(?i)\bCVE-[0-9]{4}-[0-9]{4,}\b`)
	checksumPattern      = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	activeHTMLPattern    = regexp.MustCompile(`(?is)<\s*(script|iframe|object|embed|form|meta|base|link)\b|<[^>]+\son[a-z]+\s*=`)
	fencedCodePattern    = regexp.MustCompile("(?s)```.*?```")
	inlineCodePattern    = regexp.MustCompile("`[^`\n]*`")
	stixMillisPattern    = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$`)
)

// CheckBrief validates a newly changed public brief using the strict contract.
func CheckBrief(path string, data []byte) []Issue {
	return CheckBriefWithMode(path, data, ModeStrict)
}

// CheckBriefWithMode validates a public brief. Legacy mode skips fields that
// predate append-only publication metadata, but keeps safety checks active.
func CheckBriefWithMode(path string, data []byte, mode Mode) []Issue {
	front, body, ok := splitFrontMatter(data)
	if !ok {
		return []Issue{issue(path, "frontmatter", "brief.frontmatter", "missing or malformed YAML front matter")}
	}
	var brief briefDocument
	if err := yaml.Unmarshal(front, &brief); err != nil {
		return []Issue{issue(path, "frontmatter", "brief.yaml", err.Error())}
	}

	var issues []Issue
	if strings.TrimSpace(brief.Title) == "" || strings.TrimSpace(brief.Slug) == "" {
		issues = append(issues, issue(path, "title/slug", "brief.identity", "title and slug are required"))
	}
	if mode == ModeStrict {
		if brief.BriefID == "" || brief.EventID == "" || brief.Revision < 1 || !validRFC3339(brief.ActivityAt) {
			issues = append(issues, issue(path, "brief_id,event_id,revision,activity_at", "brief.identity", "append-only identity fields are required and activity_at must be RFC3339"))
		}
		issues = append(issues, checkRevisionHistory(path, brief)...)
		issues = append(issues, checkExploitation(path, brief)...)
		issues = append(issues, checkAllowedMapFields(path, "source_assessment", brief.SourceAssessment, map[string]bool{
			"reliability": true,
			"credibility": true,
			"rating":      true,
			"likelihood":  true,
		})...)
		issues = append(issues, checkAllowedMapFields(path, "qa_status", brief.QAStatus, map[string]bool{
			"verdict":           true,
			"validation_status": true,
		})...)
		for i, cve := range brief.CVEs {
			if cve.KEVStatus != "true" && cve.KEVStatus != "false" && cve.KEVStatus != "unknown" {
				issues = append(issues, issue(path, fmt.Sprintf("cves[%d].kev_status", i), "brief.kev_status", "kev_status must be true, false, or unknown"))
			}
		}
	}

	declaredCVEs := make(map[string]bool, len(brief.CVEs))
	for _, cve := range brief.CVEs {
		declaredCVEs[strings.ToUpper(cve.ID)] = true
	}
	for _, token := range cvePattern.FindAllString(string(data), -1) {
		if !declaredCVEs[strings.ToUpper(token)] {
			issues = append(issues, issue(path, "cves", "brief.cve_undeclared", strings.ToUpper(token)+" appears in public content but is absent from structured cves"))
		}
	}

	for i, ttp := range brief.TTPs {
		if expected := mitre.TacticName(ttp.TacticID); expected == "" || ttp.TacticName != expected {
			issues = append(issues, issue(path, fmt.Sprintf("mitre_ttps[%d].tactic_name", i), "brief.attack_name", fmt.Sprintf("%s must use canonical name %q", ttp.TacticID, expected)))
		}
		techniqueID, techniqueName := ttp.TechniqueID, ttp.TechniqueName
		if ttp.SubtechniqueID != "" {
			techniqueID, techniqueName = ttp.SubtechniqueID, ttp.SubtechniqueName
		}
		if expected := mitre.TechniqueName(techniqueID); expected == "" || techniqueName != expected {
			issues = append(issues, issue(path, fmt.Sprintf("mitre_ttps[%d].technique_name", i), "brief.attack_name", fmt.Sprintf("%s must use canonical name %q", techniqueID, expected)))
		}
	}

	if (brief.Type == "threat" || brief.Type == "rumour") && len(brief.References) == 0 {
		issues = append(issues, issue(path, "references", "brief.references", brief.Type+" briefs require at least one public source"))
	}
	visibleBody := inlineCodePattern.ReplaceAllString(fencedCodePattern.ReplaceAllString(string(body), ""), "")
	if activeHTMLPattern.MatchString(visibleBody) {
		issues = append(issues, issue(path, "body", "brief.active_html", "active raw HTML is not allowed in public brief content"))
	}
	return sorted(issues)
}

// CheckBriefAppendOnly compares a changed brief with its previously published
// form. Shape validation remains the responsibility of CheckBrief; this check
// protects identity and earlier audit entries that cannot be proven from the
// current document alone.
func CheckBriefAppendOnly(path string, previous, current []byte) []Issue {
	previousFront, _, ok := splitFrontMatter(previous)
	if !ok {
		return []Issue{issue(path, "frontmatter", "brief.append_only", "previous brief has missing or malformed YAML front matter")}
	}
	currentFront, _, ok := splitFrontMatter(current)
	if !ok {
		return []Issue{issue(path, "frontmatter", "brief.append_only", "current brief has missing or malformed YAML front matter")}
	}
	var before, after briefDocument
	if err := yaml.Unmarshal(previousFront, &before); err != nil {
		return []Issue{issue(path, "frontmatter", "brief.append_only", "cannot parse previous brief: "+err.Error())}
	}
	if err := yaml.Unmarshal(currentFront, &after); err != nil {
		return []Issue{issue(path, "frontmatter", "brief.append_only", "cannot parse current brief: "+err.Error())}
	}

	var issues []Issue
	immutable := []struct {
		field  string
		before string
		after  string
	}{
		{"brief_id", before.BriefID, after.BriefID},
		{"event_id", before.EventID, after.EventID},
		{"slug", before.Slug, after.Slug},
		{"date", before.Date, after.Date},
	}
	for _, value := range immutable {
		// Legacy briefs may not have the new identity fields. Once present, the
		// strict current-document check requires them and later changes freeze them.
		if value.before != "" && value.before != value.after {
			issues = append(issues, issue(path, value.field, "brief.append_only", value.field+" is immutable after publication"))
		}
	}
	if before.Revision >= 1 && after.Revision <= before.Revision {
		issues = append(issues, issue(path, "revision", "brief.append_only", "a changed brief must advance its revision"))
	}
	historyRewritten := len(after.RevisionHistory) < len(before.RevisionHistory)
	for i := 0; !historyRewritten && i < len(before.RevisionHistory); i++ {
		historyRewritten = !reflect.DeepEqual(after.RevisionHistory[i], before.RevisionHistory[i])
	}
	if historyRewritten {
		issues = append(issues, issue(path, "revision_history", "brief.append_only", "previous revision history entries are immutable and may only be appended"))
	}
	beforeActivity, beforeErr := time.Parse(time.RFC3339, before.ActivityAt)
	afterActivity, afterErr := time.Parse(time.RFC3339, after.ActivityAt)
	if before.Revision >= 1 && beforeErr == nil && afterErr == nil && !afterActivity.After(beforeActivity) {
		issues = append(issues, issue(path, "activity_at", "brief.append_only", "a changed brief must advance activity_at"))
	}
	return sorted(issues)
}

func checkAllowedMapFields(path, field string, values map[string]interface{}, allowed map[string]bool) []Issue {
	var issues []Issue
	for key := range values {
		if !allowed[key] {
			issues = append(issues, issue(path, field+"."+key, "brief.redaction", key+" is not part of the redacted public "+field+" contract"))
		}
	}
	return issues
}

func splitFrontMatter(data []byte) ([]byte, []byte, bool) {
	normalized := bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
	if !bytes.HasPrefix(normalized, append(frontMatterDelimiter, '\n')) {
		return nil, nil, false
	}
	end := bytes.Index(normalized[4:], []byte("\n---\n"))
	if end < 0 {
		return nil, nil, false
	}
	end += 4
	return normalized[4:end], normalized[end+5:], true
}

func validRFC3339(value string) bool {
	_, err := time.Parse(time.RFC3339, value)
	return err == nil
}

func validURL(value string) bool {
	parsed, err := url.ParseRequestURI(value)
	return err == nil && (parsed.Scheme == "https" || parsed.Scheme == "http") && parsed.Host != ""
}

func checkRevisionHistory(path string, brief briefDocument) []Issue {
	if len(brief.RevisionHistory) == 0 {
		if brief.Revision == 1 {
			return nil
		}
		return []Issue{issue(path, "revision_history", "brief.revision_history", "revisions after the initial snapshot require append-only history entries")}
	}
	var issues []Issue
	if len(brief.RevisionHistory) != brief.Revision-1 {
		issues = append(issues, issue(path, "revision_history", "brief.revision_history", "revision_history must contain exactly revisions 2 through the current revision"))
	}
	var previousAt time.Time
	for i, revision := range brief.RevisionHistory {
		field := fmt.Sprintf("revision_history[%d]", i)
		expected := i + 2
		if revision.Revision != expected {
			issues = append(issues, issue(path, field+".revision", "brief.revision_order", fmt.Sprintf("revision history entry must be revision %d", expected)))
		}
		revisedAt, err := time.Parse(time.RFC3339, revision.At)
		if err != nil {
			issues = append(issues, issue(path, field+".at", "brief.revision_time", "revision timestamp must be RFC3339"))
		} else if !previousAt.IsZero() && !revisedAt.After(previousAt) {
			issues = append(issues, issue(path, field+".at", "brief.revision_time", "revision timestamps must be strictly increasing"))
		} else {
			previousAt = revisedAt
		}
		if !checksumPattern.MatchString(revision.Checksum) {
			issues = append(issues, issue(path, field+".checksum", "brief.revision_checksum", "revision checksum must be sha256:<64 lowercase hex>"))
		}
		if strings.TrimSpace(revision.Summary) == "" || len(revision.ChangedFields) == 0 {
			issues = append(issues, issue(path, field, "brief.revision_detail", "revision summary and changed_fields are required"))
		}
		for j, source := range revision.SourceURLs {
			if !validURL(source) {
				issues = append(issues, issue(path, fmt.Sprintf("%s.source_urls[%d]", field, j), "brief.revision_source", "revision source must be an absolute HTTP(S) URL"))
			}
		}
	}
	if brief.RevisionHistory[len(brief.RevisionHistory)-1].Revision != brief.Revision {
		issues = append(issues, issue(path, "revision_history", "brief.revision_history", "revision_history must end with the current revision"))
	}
	return issues
}

func checkExploitation(path string, brief briefDocument) []Issue {
	evidence := brief.ExploitationEvidence
	validStatus := evidence.Status == "confirmed_active" || evidence.Status == "not_observed" || evidence.Status == "unknown"
	if !validStatus {
		return []Issue{issue(path, "exploitation_evidence.status", "brief.exploitation", "status must be confirmed_active, not_observed, or unknown")}
	}
	var issues []Issue
	if brief.Exploited != (evidence.Status == "confirmed_active") {
		issues = append(issues, issue(path, "exploited", "brief.exploitation", "legacy exploited must be derived only from confirmed_active"))
	}
	if evidence.Status == "confirmed_active" && !validURL(evidence.SourceURL) {
		issues = append(issues, issue(path, "exploitation_evidence.source_url", "brief.exploitation", "confirmed active exploitation requires a public source URL"))
	} else if evidence.SourceURL != "" && !validURL(evidence.SourceURL) {
		issues = append(issues, issue(path, "exploitation_evidence.source_url", "brief.exploitation", "source_url must be an absolute HTTP(S) URL"))
	}
	if evidence.ObservedAt != "" && !validRFC3339(evidence.ObservedAt) {
		issues = append(issues, issue(path, "exploitation_evidence.observed_at", "brief.exploitation", "observed_at must be RFC3339"))
	}
	if evidence.Confidence != "" && evidence.Confidence != "low" && evidence.Confidence != "medium" && evidence.Confidence != "high" {
		issues = append(issues, issue(path, "exploitation_evidence.confidence", "brief.exploitation", "confidence must be low, medium, or high"))
	}
	return issues
}

type stixBundle struct {
	Type    string                   `json:"type"`
	ID      string                   `json:"id"`
	Objects []map[string]interface{} `json:"objects"`
}

// CheckSTIX validates a STIX 2.1 bundle's internal structure.
func CheckSTIX(path string, data []byte) []Issue {
	return checkSTIX(path, data, -1)
}

// CheckSTIXWithReportCount also validates the report count declared by the
// matching manifest entry.
func CheckSTIXWithReportCount(path string, data []byte, expected int) []Issue {
	return checkSTIX(path, data, expected)
}

func checkSTIX(path string, data []byte, expected int) []Issue {
	var topLevel map[string]json.RawMessage
	if err := json.Unmarshal(data, &topLevel); err != nil {
		return []Issue{issue(path, "json", "stix.json", err.Error())}
	}
	var bundle stixBundle
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&bundle); err != nil {
		return []Issue{issue(path, "json", "stix.json", err.Error())}
	}
	if bundle.Type != "bundle" || bundle.ID == "" || bundle.Objects == nil {
		return []Issue{issue(path, "type/id/objects", "stix.bundle", "STIX bundle requires type=bundle, id, and objects")}
	}

	var issues []Issue
	for key := range topLevel {
		if key != "type" && key != "id" && key != "objects" {
			issues = append(issues, issue(path, key, "stix.bundle_fields", "STIX bundle top level may contain only type, id, and objects"))
		}
	}
	byID := make(map[string][]byte, len(bundle.Objects))
	reports := 0
	for i, object := range bundle.Objects {
		id, _ := object["id"].(string)
		typeName, _ := object["type"].(string)
		field := "objects[" + strconv.Itoa(i) + "]"
		if id == "" || typeName == "" {
			issues = append(issues, issue(path, field, "stix.object", "every STIX object requires type and id"))
			continue
		}
		canonical, _ := json.Marshal(object)
		if previous, exists := byID[id]; exists {
			code := "stix.id_duplicate"
			message := "duplicate object ID " + id
			if !bytes.Equal(previous, canonical) {
				code = "stix.id_conflict"
				message = "conflicting representations share object ID " + id
			}
			issues = append(issues, issue(path, field+".id", code, message))
		} else {
			byID[id] = canonical
		}
		for _, timestamp := range []string{"created", "modified", "published", "valid_from", "valid_until", "first_seen", "last_seen"} {
			if raw, exists := object[timestamp]; exists {
				value, ok := raw.(string)
				if ok && stixMillisPattern.MatchString(value) {
					continue
				}
				issues = append(issues, issue(path, field+"."+timestamp, "stix.timestamp_precision", "STIX timestamps must be UTC with millisecond precision"))
			}
		}
		var requiredTimestamps []string
		switch typeName {
		case "identity", "report", "indicator", "attack-pattern", "threat-actor", "vulnerability", "relationship":
			requiredTimestamps = []string{"created", "modified"}
			if object["spec_version"] != "2.1" {
				issues = append(issues, issue(path, field+".spec_version", "stix.spec_version", "STIX 2.1 objects require spec_version 2.1"))
			}
		}
		if typeName == "report" {
			requiredTimestamps = append(requiredTimestamps, "published")
		} else if typeName == "indicator" {
			requiredTimestamps = append(requiredTimestamps, "valid_from")
		}
		for _, timestamp := range requiredTimestamps {
			if _, exists := object[timestamp]; !exists {
				issues = append(issues, issue(path, field+"."+timestamp, "stix.timestamp_required", typeName+" requires "+timestamp))
			}
		}
		if typeName == "software" {
			for _, name := range []string{"created_by_ref", "created", "modified"} {
				if _, exists := object[name]; exists {
					issues = append(issues, issue(path, field+"."+name, "stix.not_applicable", "software SCOs must not contain "+name))
				}
			}
		}
		if typeName == "report" {
			reports++
			refs := stringSlice(object["object_refs"])
			if len(refs) == 0 {
				issues = append(issues, issue(path, field+".object_refs", "stix.report_refs", "report must reference at least one object"))
			}
			canonicalURL, _ := object["x_craftedsignal_canonical_url"].(string)
			briefID, _ := object["x_craftedsignal_brief_id"].(string)
			if !validURL(canonicalURL) || !strings.HasPrefix(canonicalURL, "https://feed.craftedsignal.io/briefs/") {
				issues = append(issues, issue(path, field+".x_craftedsignal_canonical_url", "stix.canonical_url", "report requires a canonical CraftedSignal brief URL"))
			}
			if !hasCanonicalExternalReference(object["external_references"], briefID, canonicalURL) {
				issues = append(issues, issue(path, field+".external_references", "stix.canonical_url", "report requires matching craftedsignal external reference"))
			}
			issues = append(issues, checkSTIXReportContract(path, field, object)...)
		}
	}
	for i, object := range bundle.Objects {
		if object["type"] != "report" {
			continue
		}
		for _, ref := range stringSlice(object["object_refs"]) {
			if _, exists := byID[ref]; !exists {
				issues = append(issues, issue(path, fmt.Sprintf("objects[%d].object_refs", i), "stix.unresolved_ref", "report reference does not resolve: "+ref))
			}
		}
	}
	if expected >= 0 && reports != expected {
		issues = append(issues, issue(path, "report_count", "stix.report_count", fmt.Sprintf("manifest declares %d reports, bundle contains %d", expected, reports)))
	}
	return sorted(issues)
}

func checkSTIXReportContract(path, field string, object map[string]interface{}) []Issue {
	var issues []Issue
	for _, name := range []string{
		"x_craftedsignal_brief_id",
		"x_craftedsignal_event_id",
		"x_craftedsignal_severity",
		"x_craftedsignal_type",
	} {
		value, ok := object[name].(string)
		if !ok || strings.TrimSpace(value) == "" {
			issues = append(issues, issue(path, field+"."+name, "stix.report_contract", name+" must be a non-empty string"))
		}
	}

	revision, ok := object["x_craftedsignal_revision"].(json.Number)
	if !ok {
		issues = append(issues, issue(path, field+".x_craftedsignal_revision", "stix.report_contract", "x_craftedsignal_revision must be an integer of at least 1"))
	} else if value, err := revision.Int64(); err != nil || value < 1 {
		issues = append(issues, issue(path, field+".x_craftedsignal_revision", "stix.report_contract", "x_craftedsignal_revision must be an integer of at least 1"))
	}

	activityAt, ok := object["x_craftedsignal_activity_at"].(string)
	if !ok || !validRFC3339(activityAt) {
		issues = append(issues, issue(path, field+".x_craftedsignal_activity_at", "stix.report_contract", "x_craftedsignal_activity_at must be RFC3339"))
	}

	evidence, ok := object["x_craftedsignal_exploitation_evidence"].(map[string]interface{})
	if !ok || !validSTIXExploitationEvidence(evidence) {
		issues = append(issues, issue(path, field+".x_craftedsignal_exploitation_evidence", "stix.report_contract", "x_craftedsignal_exploitation_evidence does not match the public evidence contract"))
	}

	for _, name := range []string{"x_craftedsignal_cvss_max", "x_craftedsignal_epss_max"} {
		value, exists := object[name]
		if !exists || !isJSONNumberOrNull(value) {
			issues = append(issues, issue(path, field+"."+name, "stix.report_contract", name+" must be present as a number or null"))
		}
	}

	kevStatus, ok := object["x_craftedsignal_kev_status"].(string)
	if !ok || (kevStatus != "true" && kevStatus != "false" && kevStatus != "unknown") {
		issues = append(issues, issue(path, field+".x_craftedsignal_kev_status", "stix.report_contract", "x_craftedsignal_kev_status must be true, false, or unknown"))
	}
	return issues
}

func validSTIXExploitationEvidence(evidence map[string]interface{}) bool {
	allowed := map[string]bool{"status": true, "source_url": true, "observed_at": true, "confidence": true}
	for key := range evidence {
		if !allowed[key] {
			return false
		}
	}
	status, ok := evidence["status"].(string)
	if !ok || (status != "confirmed_active" && status != "not_observed" && status != "unknown") {
		return false
	}
	sourceURL, hasSource := evidence["source_url"].(string)
	if status == "confirmed_active" && (!hasSource || !validURL(sourceURL)) {
		return false
	}
	if hasSource && !validURL(sourceURL) {
		return false
	}
	if observedAt, exists := evidence["observed_at"]; exists {
		value, ok := observedAt.(string)
		if !ok || !validRFC3339(value) {
			return false
		}
	}
	if confidence, exists := evidence["confidence"]; exists {
		value, ok := confidence.(string)
		if !ok || (value != "low" && value != "medium" && value != "high") {
			return false
		}
	}
	return true
}

func isJSONNumberOrNull(value interface{}) bool {
	if value == nil {
		return true
	}
	_, ok := value.(json.Number)
	return ok
}

func stringSlice(value interface{}) []string {
	raw, ok := value.([]interface{})
	if !ok {
		return nil
	}
	result := make([]string, 0, len(raw))
	for _, item := range raw {
		if value, ok := item.(string); ok {
			result = append(result, value)
		}
	}
	return result
}

func hasCanonicalExternalReference(value interface{}, briefID, canonicalURL string) bool {
	references, ok := value.([]interface{})
	if !ok {
		return false
	}
	for _, raw := range references {
		reference, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		if reference["source_name"] == "craftedsignal" && reference["external_id"] == briefID && reference["url"] == canonicalURL {
			return true
		}
	}
	return false
}

type sitemap struct {
	URLs []struct {
		Location string `xml:"loc"`
	} `xml:"url"`
}

// CheckSitemap validates the XML sitemap protocol limits and canonical URL
// uniqueness.
func CheckSitemap(data []byte) []Issue {
	var document sitemap
	if err := xml.Unmarshal(data, &document); err != nil {
		return []Issue{issue("sitemap.xml", "xml", "sitemap.xml", err.Error())}
	}
	var issues []Issue
	if len(document.URLs) > 50000 {
		issues = append(issues, issue("sitemap.xml", "urlset", "sitemap.limit", fmt.Sprintf("sitemap has %d URLs; protocol limit is 50000", len(document.URLs))))
	}
	seen := make(map[string]bool, len(document.URLs))
	for i, entry := range document.URLs {
		location := strings.TrimSpace(entry.Location)
		if seen[location] {
			issues = append(issues, issue("sitemap.xml", fmt.Sprintf("url[%d].loc", i), "sitemap.duplicate", "duplicate sitemap location: "+location))
		}
		seen[location] = true
	}
	return sorted(issues)
}
