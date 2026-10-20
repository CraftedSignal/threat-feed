package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/craftedsignal/threat-feed/internal/publicfeed"
)

const manifestTestPublished = "2026-10-20T08:00:00.000Z"

func manifestTestBundle() []byte {
	return []byte(`{
  "type":"bundle",
  "id":"bundle--aaaaaaaa-aaaa-5aaa-8aaa-aaaaaaaaaaaa",
  "objects":[
    {
      "type":"identity",
      "spec_version":"2.1",
      "id":"identity--bbbbbbbb-bbbb-5bbb-8bbb-bbbbbbbbbbbb",
      "created":"2026-10-20T08:00:00.000Z",
      "modified":"2026-10-20T08:00:00.000Z",
      "name":"CraftedSignal",
      "identity_class":"organization"
    },
    {
      "type":"report",
      "spec_version":"2.1",
      "id":"report--cccccccc-cccc-5ccc-8ccc-cccccccccccc",
      "created":"2026-10-20T08:00:00.000Z",
      "modified":"2026-10-20T08:00:00.000Z",
      "published":"2026-10-20T08:00:00.000Z",
      "name":"Threat report",
      "report_types":["threat-report"],
      "object_refs":["identity--bbbbbbbb-bbbb-5bbb-8bbb-bbbbbbbbbbbb"],
      "x_craftedsignal_brief_id":"brief-001",
      "x_craftedsignal_event_id":"event-001",
      "x_craftedsignal_revision":1,
      "x_craftedsignal_canonical_url":"https://feed.craftedsignal.io/briefs/brief-001/",
      "x_craftedsignal_activity_at":"2026-10-20T08:00:00Z",
      "x_craftedsignal_severity":"critical",
      "x_craftedsignal_type":"threat",
      "x_craftedsignal_exploitation_evidence":{"status":"unknown"},
      "x_craftedsignal_cvss_max":null,
      "x_craftedsignal_epss_max":null,
      "x_craftedsignal_kev_status":"unknown",
      "external_references":[{"source_name":"craftedsignal","external_id":"brief-001","url":"https://feed.craftedsignal.io/briefs/brief-001/"}]
    }
  ]
}`)
}

func manifestTestEntry(path string, bundle []byte) map[string]interface{} {
	sum := sha256.Sum256(bundle)
	return map[string]interface{}{
		"path":            path,
		"checksum":        "sha256:" + hex.EncodeToString(sum[:]),
		"size_bytes":      len(bundle),
		"report_count":    1,
		"first_published": manifestTestPublished,
		"last_published":  manifestTestPublished,
		"generated":       "2026-10-20T09:00:00Z",
		"spec_version":    "2.1",
	}
}

func writeManifestFixture(t *testing.T, mutate func(map[string]interface{})) string {
	t.Helper()
	root := t.TempDir()
	bundle := manifestTestBundle()
	if err := os.MkdirAll(filepath.Join(root, "stix"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "stix.json"), bundle, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "stix", "2026-10.json"), bundle, 0o600); err != nil {
		t.Fatal(err)
	}
	month := manifestTestEntry("/stix/2026-10.json", bundle)
	month["month"] = "2026-10"
	index := map[string]interface{}{
		"version":      "2.0",
		"spec_version": "2.1",
		"generated":    "2026-10-20T09:00:00Z",
		"description":  "CraftedSignal STIX 2.1 bundles",
		"rolling":      manifestTestEntry("/stix.json", bundle),
		"months":       []interface{}{month},
	}
	if mutate != nil {
		mutate(index)
	}
	data, err := json.Marshal(index)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "stix", "index.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func requireManifestIssue(t *testing.T, issues []publicfeed.Issue, code string) {
	t.Helper()
	for _, item := range issues {
		if item.Code == code {
			return
		}
	}
	t.Fatalf("issues %#v do not contain %q", issues, code)
}

func TestIsSTIXPathIncludesRollingAndMonthlyArtifacts(t *testing.T) {
	for _, path := range []string{"site/static/stix.json", "site/static/stix/2026-10.json", "site/static/stix/index.json"} {
		if !isSTIXPath(path) {
			t.Errorf("isSTIXPath(%q) = false, want true", path)
		}
	}
	if isSTIXPath("site/static/feed.json") {
		t.Error("ordinary JSON Feed must not be treated as STIX")
	}
}

func TestCheckManifestAcceptsExactContractAndResolvesWebPaths(t *testing.T) {
	path := writeManifestFixture(t, nil)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if issues := checkManifest(path, data); len(issues) != 0 {
		t.Fatalf("checkManifest returned issues: %#v", issues)
	}
}

func TestCheckManifestRejectsContractAndParityViolations(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(map[string]interface{})
		code   string
	}{
		{"wrong version", func(index map[string]interface{}) { index["version"] = "1.0" }, "stix.manifest_contract"},
		{"empty months", func(index map[string]interface{}) { index["months"] = []interface{}{} }, "stix.manifest_contract"},
		{"extra top field", func(index map[string]interface{}) { index["brief_count"] = 1 }, "stix.manifest_fields"},
		{"bad checksum", func(index map[string]interface{}) {
			index["rolling"].(map[string]interface{})["checksum"] = "sha256:" + strings.Repeat("0", 64)
		}, "stix.manifest_checksum"},
		{"bad size", func(index map[string]interface{}) {
			index["rolling"].(map[string]interface{})["size_bytes"] = 7
		}, "stix.manifest_size"},
		{"bad report count", func(index map[string]interface{}) {
			index["rolling"].(map[string]interface{})["report_count"] = 2
		}, "stix.report_count"},
		{"bad bounds", func(index map[string]interface{}) {
			index["rolling"].(map[string]interface{})["first_published"] = "2026-10-19T08:00:00Z"
		}, "stix.manifest_bounds"},
		{"extra entry field", func(index map[string]interface{}) {
			index["rolling"].(map[string]interface{})["brief_count"] = 1
		}, "stix.manifest_fields"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeManifestFixture(t, tt.mutate)
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			requireManifestIssue(t, checkManifest(path, data), tt.code)
		})
	}
}

func TestCheckManifestAllowsZeroReportRollingBoundsToBeOmitted(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "stix"), 0o755); err != nil {
		t.Fatal(err)
	}
	emptyRolling := []byte(`{"type":"bundle","id":"bundle--dddddddd-dddd-5ddd-8ddd-dddddddddddd","objects":[]}`)
	monthBundle := manifestTestBundle()
	for path, data := range map[string][]byte{
		filepath.Join(root, "stix.json"):            emptyRolling,
		filepath.Join(root, "stix", "2026-10.json"): monthBundle,
	} {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	rolling := manifestTestEntry("/stix.json", emptyRolling)
	rolling["report_count"] = 0
	delete(rolling, "first_published")
	delete(rolling, "last_published")
	month := manifestTestEntry("/stix/2026-10.json", monthBundle)
	month["month"] = "2026-10"
	index := map[string]interface{}{
		"version": "2.0", "spec_version": "2.1", "generated": "2026-10-20T09:00:00Z",
		"description": "CraftedSignal STIX 2.1 bundles", "rolling": rolling, "months": []interface{}{month},
	}
	data, err := json.Marshal(index)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "stix", "index.json")
	if issues := checkManifest(path, data); len(issues) != 0 {
		t.Fatalf("checkManifest returned issues: %#v", issues)
	}
}
