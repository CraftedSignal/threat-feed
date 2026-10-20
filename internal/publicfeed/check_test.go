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

func TestCheckBriefRejectsSemanticViolations(t *testing.T) {
	tests := []struct {
		name string
		edit func(string) string
		code string
	}{
		{"missing identity", func(s string) string { return strings.Replace(s, "brief_id: brief-001\n", "", 1) }, "brief.identity"},
		{"missing revision history", func(s string) string { return strings.Replace(s, "revision_history:\n", "history_missing:\n", 1) }, "brief.revision_history"},
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
		{"active raw html", func(s string) string { return s + "\n<script>alert(1)</script>\n" }, "brief.active_html"},
		{"invalid kev tri-state", func(s string) string { return strings.Replace(s, `kev_status: "unknown"`, `kev_status: "yes"`, 1) }, "brief.kev_status"},
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
	  "x_craftedsignal_activity_at": "2026-10-20T08:00:00.000Z",
	  "x_craftedsignal_canonical_url": "https://feed.craftedsignal.io/briefs/confirmed-threat-activity/",
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
		{"missing canonical url", strings.Replace(validSTIX(1), "\t  \"x_craftedsignal_canonical_url\": \"https://feed.craftedsignal.io/briefs/confirmed-threat-activity/\",\n", "", 1), "stix.canonical_url"},
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
