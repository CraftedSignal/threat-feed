package compiler

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// DefaultMaxBriefAge is the default cutoff for briefs included in a bundle.
// Briefs with published_at older than this are excluded during compilation.
const DefaultMaxBriefAge = 5 * 365 * 24 * time.Hour // ~5 years

// BundleManifest is the outer JSON envelope (matches backend BundleManifest).
type BundleManifest struct {
	Version     string `json:"version"`
	PublishedAt string `json:"published_at"`
	Checksum    string `json:"checksum"`
	Content     string `json:"content"`
}

// BundleContent is the decrypted payload (matches backend BundleContent).
type BundleContent struct {
	Briefs []BundleBrief `json:"briefs"`
}

// BundleBrief matches the backend bundle format exactly.
type BundleBrief struct {
	ID          string       `json:"id"`
	Slug        string       `json:"slug"`
	Title       string       `json:"title"`
	Summary     string       `json:"summary"`
	Content     string       `json:"content,omitempty"`
	Severity    string       `json:"severity"`
	ThreatActor string       `json:"threat_actor,omitempty"`
	PublishedAt string       `json:"published_at"`
	Tags        []string     `json:"tags,omitempty"`
	References  []string     `json:"references,omitempty"`
	Rules       []BundleRule `json:"rules"`
	IOCs        []BundleIOC  `json:"iocs,omitempty"`
	TTPs        []BundleTTP  `json:"ttps,omitempty"`
}

// BundleRule matches the backend.
type BundleRule struct {
	Title       string           `json:"title"`
	Description string           `json:"description,omitempty"`
	Query       string           `json:"query"`
	Platform    string           `json:"platform"`
	Severity    string           `json:"severity"`
	Tactics     []string         `json:"tactics,omitempty"`
	Techniques  []string         `json:"techniques,omitempty"`
	DataSources []string         `json:"data_sources,omitempty"`
	Tests       *BundleTestSuite `json:"tests,omitempty"`
}

// BundleTestSuite matches the backend.
type BundleTestSuite struct {
	Positive []BundleTestCase `json:"positive,omitempty"`
	Negative []BundleTestCase `json:"negative,omitempty"`
}

// BundleTestCase matches the backend.
type BundleTestCase struct {
	Name        string                   `json:"name"`
	Description string                   `json:"description,omitempty"`
	Data        []map[string]interface{} `json:"data,omitempty"`
}

// BundleIOC matches the backend.
type BundleIOC struct {
	Type    string `json:"type"`
	Value   string `json:"value"`
	Context string `json:"context,omitempty"`
}

// BundleTTP matches the backend.
type BundleTTP struct {
	TacticID         string `json:"tactic_id"`
	TacticName       string `json:"tactic_name,omitempty"`
	TechniqueID      string `json:"technique_id"`
	TechniqueName    string `json:"technique_name,omitempty"`
	SubtechniqueID   string `json:"subtechnique_id,omitempty"`
	SubtechniqueName string `json:"subtechnique_name,omitempty"`
}

// LoadBriefs reads all YAML files from the given directory.
func LoadBriefs(dir string) ([]Brief, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading briefs directory: %w", err)
	}

	var briefs []Brief
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			continue
		}

		path := filepath.Join(dir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", path, err)
		}

		var b Brief
		if err := yaml.Unmarshal(data, &b); err != nil {
			return nil, fmt.Errorf("parsing %s: %w", path, err)
		}

		if err := validateBrief(&b, name); err != nil {
			return nil, err
		}

		briefs = append(briefs, b)
	}

	// Sort by published_at descending for deterministic output
	sort.Slice(briefs, func(i, j int) bool {
		return briefs[i].PublishedAt > briefs[j].PublishedAt
	})

	return briefs, nil
}

func validateBrief(b *Brief, filename string) error {
	if b.ID == "" {
		return fmt.Errorf("%s: missing required field 'id'", filename)
	}
	if b.Slug == "" {
		return fmt.Errorf("%s: missing required field 'slug'", filename)
	}
	if b.Title == "" {
		return fmt.Errorf("%s: missing required field 'title'", filename)
	}
	if b.Summary == "" {
		return fmt.Errorf("%s: missing required field 'summary'", filename)
	}
	if b.Severity == "" {
		return fmt.Errorf("%s: missing required field 'severity'", filename)
	}
	if b.PublishedAt == "" {
		return fmt.Errorf("%s: missing required field 'published_at'", filename)
	}
	for i, r := range b.Rules {
		if r.Title == "" {
			return fmt.Errorf("%s: rule[%d]: missing title", filename, i)
		}
		if r.Query == "" {
			return fmt.Errorf("%s: rule[%d] %q: missing query", filename, i, r.Title)
		}
		if r.Platform == "" {
			return fmt.Errorf("%s: rule[%d] %q: missing platform", filename, i, r.Title)
		}
	}
	return nil
}

// Compile converts YAML briefs into a BundleContent.
// Briefs with published_at older than maxAge are excluded. Use 0 to include all.
func Compile(briefs []Brief, maxAge time.Duration) *BundleContent {
	cutoff := time.Time{}
	if maxAge > 0 {
		cutoff = time.Now().Add(-maxAge)
	}

	content := &BundleContent{}
	for _, b := range briefs {
		if !cutoff.IsZero() {
			if t, err := time.Parse(time.RFC3339, b.PublishedAt); err == nil && t.Before(cutoff) {
				continue
			}
		}
		bb := BundleBrief{
			ID:          b.ID,
			Slug:        b.Slug,
			Title:       b.Title,
			Summary:     b.Summary,
			Content:     b.Content,
			Severity:    b.Severity,
			ThreatActor: b.ThreatActor,
			PublishedAt: b.PublishedAt,
			Tags:        b.Tags,
			References:  b.References,
		}
		for _, r := range b.Rules {
			br := BundleRule{
				Title:       r.Title,
				Description: r.Description,
				Query:       r.Query,
				Platform:    r.Platform,
				Severity:    r.Severity,
				Tactics:     r.Tactics,
				Techniques:  r.Techniques,
				DataSources: r.DataSources,
			}
			if r.Tests != nil {
				br.Tests = &BundleTestSuite{}
				for _, tc := range r.Tests.Positive {
					br.Tests.Positive = append(br.Tests.Positive, BundleTestCase{
						Name:        tc.Name,
						Description: tc.Description,
						Data:        tc.Data,
					})
				}
				for _, tc := range r.Tests.Negative {
					br.Tests.Negative = append(br.Tests.Negative, BundleTestCase{
						Name:        tc.Name,
						Description: tc.Description,
						Data:        tc.Data,
					})
				}
			}
			bb.Rules = append(bb.Rules, br)
		}
		for _, ioc := range b.IOCs {
			bb.IOCs = append(bb.IOCs, BundleIOC{
				Type:    ioc.Type,
				Value:   ioc.Value,
				Context: ioc.Context,
			})
		}
		for _, ttp := range b.TTPs {
			bb.TTPs = append(bb.TTPs, BundleTTP{
				TacticID:         ttp.TacticID,
				TacticName:       ttp.TacticName,
				TechniqueID:      ttp.TechniqueID,
				TechniqueName:    ttp.TechniqueName,
				SubtechniqueID:   ttp.SubtechniqueID,
				SubtechniqueName: ttp.SubtechniqueName,
			})
		}
		content.Briefs = append(content.Briefs, bb)
	}
	return content
}

// DeriveKey derives an AES-256 encryption key from an Ed25519 public key.
// Must match the backend's DeriveKey in backend/pkg/threatfeed/decrypt.go.
func DeriveKey(publicKeyHex string) ([]byte, error) {
	pubKey, err := hex.DecodeString(publicKeyHex)
	if err != nil || len(pubKey) != 32 {
		return nil, fmt.Errorf("invalid public key: must be 64 hex characters (32 bytes Ed25519)")
	}
	h := sha256.New()
	h.Write(pubKey)
	h.Write([]byte("craftedsignal-threat-feed-v1"))
	return h.Sum(nil), nil // 32 bytes = AES-256
}

// Encrypt produces an encrypted BundleManifest from content using a key derived from the Ed25519 public key.
func Encrypt(content *BundleContent, version, publishedAt, publicKeyHex string) (*BundleManifest, error) {
	key, err := DeriveKey(publicKeyHex)
	if err != nil {
		return nil, err
	}

	plaintext, err := json.Marshal(content)
	if err != nil {
		return nil, fmt.Errorf("marshaling content: %w", err)
	}

	hash := sha256.Sum256(plaintext)
	checksum := hex.EncodeToString(hash[:])

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creating cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generating nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	return &BundleManifest{
		Version:     version,
		PublishedAt: publishedAt,
		Checksum:    checksum,
		Content:     base64.StdEncoding.EncodeToString(ciphertext),
	}, nil
}
