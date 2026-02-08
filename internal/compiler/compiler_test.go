package compiler

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// testPublicKey generates a random Ed25519 key pair and returns the public key as hex.
func testPublicKey() string {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	return hex.EncodeToString(pub)
}

func TestLoadBriefs(t *testing.T) {
	dir := t.TempDir()

	yaml := `
id: "test-brief"
slug: "2026-test"
title: "Test Brief"
summary: "Summary"
severity: "high"
published_at: "2026-01-01T00:00:00Z"
rules:
  - title: "Rule 1"
    query: "index=main"
    platform: "spl"
    severity: "high"
iocs:
  - type: ip
    value: "1.2.3.4"
ttps:
  - tactic_id: "TA0001"
    technique_id: "T1566"
`
	if err := os.WriteFile(filepath.Join(dir, "test.yaml"), []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}

	briefs, err := LoadBriefs(dir)
	if err != nil {
		t.Fatalf("LoadBriefs: %v", err)
	}
	if len(briefs) != 1 {
		t.Fatalf("expected 1 brief, got %d", len(briefs))
	}
	if briefs[0].ID != "test-brief" {
		t.Errorf("ID = %q, want test-brief", briefs[0].ID)
	}
	if len(briefs[0].Rules) != 1 {
		t.Errorf("rules = %d, want 1", len(briefs[0].Rules))
	}
	if len(briefs[0].IOCs) != 1 {
		t.Errorf("iocs = %d, want 1", len(briefs[0].IOCs))
	}
}

func TestLoadBriefs_Validation(t *testing.T) {
	dir := t.TempDir()

	// Missing ID
	yaml := `
slug: "test"
title: "Test"
summary: "S"
severity: "high"
published_at: "2026-01-01T00:00:00Z"
`
	if err := os.WriteFile(filepath.Join(dir, "bad.yaml"), []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadBriefs(dir)
	if err == nil {
		t.Fatal("expected validation error for missing ID")
	}
}

func TestCompileAndEncrypt(t *testing.T) {
	briefs := []Brief{
		{
			ID:          "b1",
			Slug:        "b1-slug",
			Title:       "Brief One",
			Summary:     "Summary",
			Severity:    "high",
			PublishedAt: "2026-01-01T00:00:00Z",
			Rules: []Rule{
				{
					Title:    "R1",
					Query:    "index=main",
					Platform: "spl",
					Severity: "high",
					Tests: &TestData{
						Positive: []TestCase{
							{Name: "pos1", Data: []map[string]interface{}{{"key": "val"}}},
						},
					},
				},
			},
			IOCs: []IOC{{Type: "ip", Value: "10.0.0.1"}},
			TTPs: []TTP{{TacticID: "TA0001", TechniqueID: "T1566"}},
		},
	}

	content := Compile(briefs, 0) // 0 = no cutoff
	if len(content.Briefs) != 1 {
		t.Fatalf("expected 1 brief, got %d", len(content.Briefs))
	}
	if content.Briefs[0].Rules[0].Tests == nil {
		t.Fatal("expected tests on rule")
	}
	if len(content.Briefs[0].Rules[0].Tests.Positive) != 1 {
		t.Error("expected 1 positive test")
	}

	publicKey := testPublicKey()
	manifest, err := Encrypt(content, "v1.0.0", "2026-01-01T00:00:00Z", publicKey)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if manifest.Version != "v1.0.0" {
		t.Errorf("version = %q, want v1.0.0", manifest.Version)
	}
	if manifest.Content == "" {
		t.Error("expected non-empty encrypted content")
	}
	if manifest.Checksum == "" {
		t.Error("expected non-empty checksum")
	}

	// Verify it's valid JSON
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("Marshal manifest: %v", err)
	}
	if len(data) == 0 {
		t.Error("expected non-empty manifest JSON")
	}
}

func TestDeriveKey(t *testing.T) {
	pubKey := testPublicKey()

	key1, err := DeriveKey(pubKey)
	if err != nil {
		t.Fatalf("DeriveKey failed: %v", err)
	}
	if len(key1) != 32 {
		t.Errorf("expected 32-byte key, got %d", len(key1))
	}

	// Same public key produces same derived key
	key2, err := DeriveKey(pubKey)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(key1) != hex.EncodeToString(key2) {
		t.Error("same public key should produce same derived key")
	}
}

func TestCompile_MaxAgeCutoff(t *testing.T) {
	recent := time.Now().Add(-30 * 24 * time.Hour).Format(time.RFC3339)   // 30 days ago
	old := time.Now().Add(-6 * 365 * 24 * time.Hour).Format(time.RFC3339) // 6 years ago

	briefs := []Brief{
		{ID: "recent", Slug: "recent", Title: "Recent", Summary: "S", Severity: "high", PublishedAt: recent},
		{ID: "old", Slug: "old", Title: "Old", Summary: "S", Severity: "low", PublishedAt: old},
	}

	// With default 5y cutoff: old brief (6y) excluded
	content := Compile(briefs, DefaultMaxBriefAge)
	if len(content.Briefs) != 1 {
		t.Fatalf("expected 1 brief with 5y cutoff, got %d", len(content.Briefs))
	}
	if content.Briefs[0].ID != "recent" {
		t.Errorf("expected recent brief, got %s", content.Briefs[0].ID)
	}

	// With 0 cutoff: all included
	content = Compile(briefs, 0)
	if len(content.Briefs) != 2 {
		t.Fatalf("expected 2 briefs with no cutoff, got %d", len(content.Briefs))
	}

	// With 10y cutoff: both included
	content = Compile(briefs, 10*365*24*time.Hour)
	if len(content.Briefs) != 2 {
		t.Fatalf("expected 2 briefs with 10y cutoff, got %d", len(content.Briefs))
	}
}

func TestEncrypt_InvalidKey(t *testing.T) {
	content := &BundleContent{Briefs: []BundleBrief{{ID: "b1"}}}

	_, err := Encrypt(content, "v1", "2026-01-01", "not-valid-hex")
	if err == nil {
		t.Error("expected error for invalid key")
	}

	_, err = Encrypt(content, "v1", "2026-01-01", "abcd")
	if err == nil {
		t.Error("expected error for short key")
	}
}
