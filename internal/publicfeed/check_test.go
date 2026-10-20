package publicfeed

import (
	"fmt"
	"strings"
	"testing"
)

const validBrief = `---
title: Confirmed threat activity
slug: confirmed-threat-activity
brief_id: brief-001
event_id: event-001
revision: 2
activity_at: "2026-10-20T08:00:00Z"
date: "2026-10-19T08:00:00Z"
type: threat
exploited: true
exploitation_evidence:
  status: confirmed_active
  source_url: https://example.com/advisory
  observed_at: "2026-10-20T07:00:00Z"
  confidence: high
source_assessment:
  reliability: A
  credibility: 1
  rating: high
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: validated
cves:
  - id: CVE-2026-1234
    kev_status: "unknown"
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://example.com/advisory
revision_history:
  - revision: 2
    at: "2026-10-20T08:00:00Z"
    checksum: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    summary: Confirmed exploitation evidence.
    changed_fields: [exploitation_evidence]
    source_urls: [https://example.com/advisory]
---

CVE-2026-1234 is being exploited. No active HTML is present.
`

func issueCodes(issues []Issue) string {
	codes := make([]string, 0, len(issues))
	for _, issue := range issues {
		codes = append(codes, issue.Code)
	}
	return strings.Join(codes, ",")
}

func requireIssue(t *testing.T, issues []Issue, code string) {
	t.Helper()
	for _, issue := range issues {
		if issue.Code == code {
			return
		}
	}
	t.Fatalf("issues %s do not contain %q", issueCodes(issues), code)
}

func TestCheckBriefAcceptsStrictContract(t *testing.T) {
	if issues := CheckBrief("brief.md", []byte(validBrief)); len(issues) != 0 {
		t.Fatalf("CheckBrief returned issues: %#v", issues)
	}
}

func TestCheckBriefAcceptsInitialRevisionWithoutHistory(t *testing.T) {
	initial := strings.Replace(validBrief, "revision: 2\nactivity_at:", "revision: 1\nactivity_at:", 1)
	initial = strings.Replace(initial, `activity_at: "2026-10-20T08:00:00Z"`, `activity_at: "2026-10-19T08:00:00Z"`, 1)
	historyStart := strings.Index(initial, "revision_history:\n")
	if historyStart < 0 {
		t.Fatal("validBrief revision history fixture is malformed")
	}
	historyEnd := strings.Index(initial[historyStart:], "---\n\n")
	if historyEnd < 0 {
		t.Fatal("validBrief revision history fixture is malformed")
	}
	initial = initial[:historyStart] + initial[historyStart+historyEnd:]
	if issues := CheckBrief("initial.md", []byte(initial)); len(issues) != 0 {
		t.Fatalf("CheckBrief returned issues for initial revision: %#v", issues)
	}
}

func TestCheckBriefAppendOnlyAcceptsOneNewMaterialRevision(t *testing.T) {
	previous := strings.Replace(validBrief, "revision: 2\nactivity_at: \"2026-10-20T08:00:00Z\"", "revision: 1\nactivity_at: \"2026-10-20T07:00:00Z\"", 1)
	historyStart := strings.Index(previous, "revision_history:\n")
	historyEnd := strings.Index(previous[historyStart:], "---\n\n")
	previous = previous[:historyStart] + previous[historyStart+historyEnd:]

	if issues := CheckBriefAppendOnly("brief.md", []byte(previous), []byte(validBrief)); len(issues) != 0 {
		t.Fatalf("CheckBriefAppendOnly returned issues: %#v", issues)
	}
}

func TestCheckBriefAcceptsMaintenanceRevisionWithoutAdvancingActivity(t *testing.T) {
	maintenance := strings.Replace(validBrief, "revision: 2\n", "revision: 3\n", 1)
	maintenance = strings.Replace(maintenance, "---\n\nCVE", "  - revision: 3\n    at: \"2026-10-21T08:00:00Z\"\n    checksum: sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n    summary: Repaired a legacy identity collision.\n    changed_fields: [slug]\n    maintenance: true\n---\n\nCVE", 1)
	if issues := CheckBrief("brief.md", []byte(maintenance)); len(issues) != 0 {
		t.Fatalf("maintenance revision failed current-document validation: %#v", issues)
	}
	if issues := CheckBriefAppendOnly("brief.md", []byte(validBrief), []byte(maintenance)); len(issues) != 0 {
		t.Fatalf("maintenance revision failed append-only validation: %#v", issues)
	}
}

func TestCheckBriefDoesNotTreatComparisonTextAsActiveHTML(t *testing.T) {
	text := validBrief + "\nVersions <= 3.2.5 may expose an onerror= payload before a later > marker.\n"
	if issues := CheckBrief("brief.md", []byte(text)); strings.Contains(issueCodes(issues), "brief.active_html") {
		t.Fatalf("comparison text was treated as active HTML: %#v", issues)
	}
}

func TestCheckBriefAppendOnlyRejectsIdentityAndHistoryRewrites(t *testing.T) {
	previous := strings.Replace(validBrief, "revision: 2\nactivity_at: \"2026-10-20T08:00:00Z\"", "revision: 3\nactivity_at: \"2026-10-20T09:00:00Z\"", 1)
	previous = strings.Replace(previous, "---\n\nCVE", "  - revision: 3\n    at: \"2026-10-20T09:00:00Z\"\n    checksum: sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\n    summary: Updated affected versions.\n    changed_fields: [affected_versions]\n    source_urls: [https://example.com/advisory]\n---\n\nCVE", 1)
	current := strings.Replace(previous, "revision: 3\nactivity_at: \"2026-10-20T09:00:00Z\"", "revision: 4\nactivity_at: \"2026-10-20T10:00:00Z\"", 1)
	current = strings.Replace(current, "---\n\nCVE", "  - revision: 4\n    at: \"2026-10-20T10:00:00Z\"\n    checksum: sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n    summary: Added a new source.\n    changed_fields: [references]\n    source_urls: [https://example.com/new]\n---\n\nCVE", 1)

	tests := []struct {
		name string
		edit func(string) string
	}{
		{"brief id", func(s string) string { return strings.Replace(s, "brief_id: brief-001", "brief_id: brief-002", 1) }},
		{"event id", func(s string) string { return strings.Replace(s, "event_id: event-001", "event_id: event-002", 1) }},
		{"slug", func(s string) string {
			return strings.Replace(s, "slug: confirmed-threat-activity", "slug: changed", 1)
		}},
		{"publication date", func(s string) string { return strings.Replace(s, "2026-10-19T08:00:00Z", "2026-10-18T08:00:00Z", 1) }},
		{"prior revision", func(s string) string {
			return strings.Replace(s, "summary: Confirmed exploitation evidence.", "summary: Rewritten history.", 1)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			requireIssue(t, CheckBriefAppendOnly("brief.md", []byte(previous), []byte(tt.edit(current))), "brief.append_only")
		})
	}
}

func TestCheckBriefAppendOnlyRequiresRevisionAdvance(t *testing.T) {
	requireIssue(t, CheckBriefAppendOnly("brief.md", []byte(validBrief), []byte(validBrief)), "brief.append_only")
}

func TestCheckBriefAppendOnlyAllowsLegacyDocumentToEstablishInitialSnapshot(t *testing.T) {
	legacy := strings.Replace(validBrief, "brief_id: brief-001\nevent_id: event-001\nrevision: 2\n", "", 1)
	if issues := CheckBriefAppendOnly("brief.md", []byte(legacy), []byte(validBrief)); len(issues) != 0 {
		t.Fatalf("legacy initial snapshot returned issues: %#v", issues)
	}
}

func TestCheckBriefRejectsSemanticViolations(t *testing.T) {
	tests := []struct {
		name string
		edit func(string) string
		code string
	}{
		{"missing identity", func(s string) string { return strings.Replace(s, "brief_id: brief-001\n", "", 1) }, "brief.identity"},
		{"invalid publication date", func(s string) string {
			return strings.Replace(s, `date: "2026-10-19T08:00:00Z"`, `date: "yesterday"`, 1)
		}, "brief.identity"},
		{"missing revision history", func(s string) string { return strings.Replace(s, "revision_history:\n", "history_missing:\n", 1) }, "brief.revision_history"},
		{"activity before latest revision", func(s string) string {
			return strings.Replace(s, `activity_at: "2026-10-20T08:00:00Z"`, `activity_at: "2026-10-20T07:00:00Z"`, 1)
		}, "brief.activity_at"},
		{"activity after latest revision", func(s string) string {
			return strings.Replace(s, `activity_at: "2026-10-20T08:00:00Z"`, `activity_at: "2026-10-21T08:00:00Z"`, 1)
		}, "brief.activity_at"},
		{"bad revision checksum", func(s string) string {
			return strings.Replace(s, "sha256:"+strings.Repeat("a", 64), "not-a-checksum", 1)
		}, "brief.revision_checksum"},
		{"undeclared cve", func(s string) string { return s + "\nCVE-2026-9999\n" }, "brief.cve_undeclared"},
		{"noncanonical attack name", func(s string) string {
			return strings.Replace(s, "technique_name: Exploit Public-Facing Application", "technique_name: Public app exploit", 1)
		}, "brief.attack_name"},
		{"unsourced threat", func(s string) string {
			return strings.Replace(s, "references:\n  - https://example.com/advisory", "references: []", 1)
		}, "brief.references"},
		{"contradictory exploit evidence", func(s string) string {
			return strings.Replace(s, "status: confirmed_active", "status: not_observed", 1)
		}, "brief.exploitation"},
		{"invalid optional exploit source", func(s string) string {
			s = strings.Replace(s, "exploited: true", "exploited: false", 1)
			s = strings.Replace(s, "status: confirmed_active", "status: unknown", 1)
			return strings.Replace(s, "source_url: https://example.com/advisory", "source_url: not-a-url", 1)
		}, "brief.exploitation"},
		{"active raw html", func(s string) string { return s + "\n<script>alert(1)</script>\n" }, "brief.active_html"},
		{"invalid kev tri-state", func(s string) string { return strings.Replace(s, `kev_status: "unknown"`, `kev_status: "yes"`, 1) }, "brief.kev_status"},
		{"private source assessment field", func(s string) string {
			return strings.Replace(s, "  likelihood: likely", "  likelihood: likely\n  corroboration: private narrative", 1)
		}, "brief.redaction"},
		{"private qa field", func(s string) string {
			return strings.Replace(s, "  validation_status: validated", "  validation_status: validated\n  gaps: [private]", 1)
		}, "brief.redaction"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			requireIssue(t, CheckBrief("brief.md", []byte(tt.edit(validBrief))), tt.code)
		})
	}
}

func TestCheckBriefLegacyModeIsExplicit(t *testing.T) {
	legacy := `---
title: Legacy advisory
slug: legacy-advisory
date: "2024-01-01T00:00:00Z"
type: advisory
references: [https://example.com/old]
---
Old content.
`
	strict := CheckBrief("legacy.md", []byte(legacy))
	requireIssue(t, strict, "brief.identity")
	if issues := CheckBriefWithMode("legacy.md", []byte(legacy), ModeLegacy); len(issues) != 0 {
		t.Fatalf("legacy mode returned issues: %#v", issues)
	}
}

func validSTIX(reportCount int) string {
	_ = reportCount
	return `{
  "type": "bundle",
  "id": "bundle--aaaaaaaa-aaaa-5aaa-8aaa-aaaaaaaaaaaa",
  "objects": [
    {
      "type": "identity",
      "spec_version": "2.1",
      "id": "identity--bbbbbbbb-bbbb-5bbb-8bbb-bbbbbbbbbbbb",
      "created": "2026-10-20T08:00:00.000Z",
      "modified": "2026-10-20T08:00:00.000Z",
      "name": "CraftedSignal",
      "identity_class": "organization"
    },
    {
      "type": "software",
      "spec_version": "2.1",
      "id": "software--dddddddd-dddd-5ddd-8ddd-dddddddddddd",
      "name": "Example product"
    },
    {
      "type": "report",
      "spec_version": "2.1",
      "id": "report--cccccccc-cccc-5ccc-8ccc-cccccccccccc",
      "created": "2026-10-20T08:00:00.000Z",
      "modified": "2026-10-20T08:00:00.000Z",
      "published": "2026-10-20T08:00:00.000Z",
      "name": "Threat report",
      "report_types": ["threat-report"],
      "object_refs": ["identity--bbbbbbbb-bbbb-5bbb-8bbb-bbbbbbbbbbbb"],
      "x_craftedsignal_brief_id": "brief-001",
	  "x_craftedsignal_event_id": "event-001",
	  "x_craftedsignal_revision": 2,
	  "x_craftedsignal_activity_at": "2026-10-20T08:00:00Z",
	  "x_craftedsignal_canonical_url": "https://feed.craftedsignal.io/briefs/confirmed-threat-activity/",
	  "x_craftedsignal_severity": "critical",
	  "x_craftedsignal_type": "threat",
	  "x_craftedsignal_exploitation_evidence": {"status":"confirmed_active","source_url":"https://example.com/advisory","observed_at":"2026-10-20T07:00:00Z","confidence":"high"},
	  "x_craftedsignal_epss_max": 0.91,
	  "x_craftedsignal_kev_status": "unknown",
	  "external_references": [{"source_name":"craftedsignal","external_id":"brief-001","url":"https://feed.craftedsignal.io/briefs/confirmed-threat-activity/"}]
    }
  ]
}`
}

func TestCheckSTIXAcceptsCanonicalBundle(t *testing.T) {
	if issues := CheckSTIX("bundle.json", []byte(validSTIX(1))); len(issues) != 0 {
		t.Fatalf("CheckSTIX returned issues: %#v", issues)
	}
}

func TestCheckSTIXRejectsStructuralViolations(t *testing.T) {
	tests := []struct {
		name string
		data string
		code string
	}{
		{"duplicate ids", strings.Replace(validSTIX(1), "\n  ]\n}", "\n    ,{\"type\":\"identity\",\"id\":\"identity--bbbbbbbb-bbbb-5bbb-8bbb-bbbbbbbbbbbb\",\"name\":\"Other\"}\n  ]\n}", 1), "stix.id_conflict"},
		{"missing report refs", strings.Replace(validSTIX(1), `"object_refs": ["identity--bbbbbbbb-bbbb-5bbb-8bbb-bbbbbbbbbbbb"]`, `"object_refs": []`, 1), "stix.report_refs"},
		{"unresolved report refs", strings.Replace(validSTIX(1), `identity--bbbbbbbb-bbbb-5bbb-8bbb-bbbbbbbbbbbb"]`, `identity--dddddddd-dddd-5ddd-8ddd-dddddddddddd"]`, 1), "stix.unresolved_ref"},
		{"imprecise timestamps", strings.ReplaceAll(validSTIX(1), ".000Z", "Z"), "stix.timestamp_precision"},
		{"missing report timestamp", strings.Replace(validSTIX(1), "      \"published\": \"2026-10-20T08:00:00.000Z\",\n", "", 1), "stix.timestamp_required"},
		{"software versioning fields", strings.Replace(validSTIX(1), "      \"id\": \"software--dddddddd-dddd-5ddd-8ddd-dddddddddddd\",", "      \"id\": \"software--dddddddd-dddd-5ddd-8ddd-dddddddddddd\",\n      \"created\": \"2026-10-20T08:00:00.000Z\",", 1), "stix.not_applicable"},
		{"missing canonical url", strings.Replace(validSTIX(1), "\t  \"x_craftedsignal_canonical_url\": \"https://feed.craftedsignal.io/briefs/confirmed-threat-activity/\",\n", "", 1), "stix.canonical_url"},
		{"null score", strings.Replace(validSTIX(1), "\t  \"x_craftedsignal_epss_max\": 0.91,\n", "\t  \"x_craftedsignal_cvss_max\": null,\n\t  \"x_craftedsignal_epss_max\": 0.91,\n", 1), "stix.null"},
		{"nested null", strings.Replace(validSTIX(1), `"confidence":"high"`, `"confidence":"high","detail":null`, 1), "stix.null"},
		{"invalid external reference URL", strings.Replace(validSTIX(1), `"url":"https://feed.craftedsignal.io/briefs/confirmed-threat-activity/"`, `"url":"CVE-2026-67279"`, 1), "stix.external_reference"},
		{"invalid score", strings.Replace(validSTIX(1), "\"x_craftedsignal_epss_max\": 0.91", "\"x_craftedsignal_epss_max\": \"high\"", 1), "stix.report_contract"},
		{"invalid revision", strings.Replace(validSTIX(1), "\"x_craftedsignal_revision\": 2", "\"x_craftedsignal_revision\": 2.5", 1), "stix.report_contract"},
		{"invalid kev status", strings.Replace(validSTIX(1), "\"x_craftedsignal_kev_status\": \"unknown\"", "\"x_craftedsignal_kev_status\": \"yes\"", 1), "stix.report_contract"},
		{"invalid exploitation evidence", strings.Replace(validSTIX(1), "\"status\":\"confirmed_active\"", "\"status\":\"observed\"", 1), "stix.report_contract"},
		{"extra bundle field", strings.Replace(validSTIX(1), "\"objects\": [", "\"spec_version\": \"2.1\",\n  \"objects\": [", 1), "stix.bundle_fields"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			requireIssue(t, CheckSTIX("bundle.json", []byte(tt.data)), tt.code)
		})
	}
	requireIssue(t, CheckSTIXWithReportCount("bundle.json", []byte(validSTIX(1)), 2), "stix.report_count")
}

func TestCheckSitemapRejectsDuplicatesAndProtocolOverflow(t *testing.T) {
	duplicate := []byte(`<?xml version="1.0"?><urlset><url><loc>https://feed.craftedsignal.io/a/</loc></url><url><loc>https://feed.craftedsignal.io/a/</loc></url></urlset>`)
	requireIssue(t, CheckSitemap(duplicate), "sitemap.duplicate")

	var large strings.Builder
	large.WriteString(`<urlset>`)
	for i := 0; i < 50001; i++ {
		fmt.Fprintf(&large, `<url><loc>https://feed.craftedsignal.io/%d/</loc></url>`, i)
	}
	large.WriteString(`</urlset>`)
	requireIssue(t, CheckSitemap([]byte(large.String())), "sitemap.limit")
}
