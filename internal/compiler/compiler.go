package compiler

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/craftedsignal/threat-feed/internal/mitre"
	"github.com/craftedsignal/threat-feed/pkg/ioc"
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
	Briefs  []BundleBrief  `json:"briefs"`
	Digests []BundleDigest `json:"digests,omitempty"`
}

// BundleDigest is a periodic digest (daily or weekly) summarising recent briefs.
type BundleDigest struct {
	ID            string `json:"id"`
	Type          string `json:"type"` // "daily_digest" or "weekly_digest"
	Title         string `json:"title"`
	Summary       string `json:"summary"`
	Content       string `json:"content"` // Markdown
	Period        string `json:"period"`
	LookbackHours int    `json:"lookback_hours"`
	TotalBriefs   int    `json:"total_briefs"`
	PublishedAt   string `json:"published_at"`
}

// BundleBrief matches the backend bundle format exactly.
type BundleBrief struct {
	ID          string       `json:"id"`
	Slug        string       `json:"slug"`
	Title       string       `json:"title"`
	Summary     string       `json:"summary"`
	Content     string       `json:"content,omitempty"`
	Type        string       `json:"type,omitempty"`
	Severity    string       `json:"severity"`
	ThreatActor string       `json:"threat_actor,omitempty"`
	PublishedAt string       `json:"published_at"`
	Tags        []string     `json:"tags,omitempty"`
	References  []string     `json:"references,omitempty"`
	Rules       []BundleRule `json:"rules"`
	IOCs        []BundleIOC  `json:"iocs,omitempty"`
	TTPs        []BundleTTP  `json:"ttps,omitempty"`

	SourceAssessment *BundleSourceAssessment `json:"source_assessment,omitempty"`
	QAStatus         *BundleQAStatus         `json:"qa_status,omitempty"`
	ActionPlan       *BundleActionPlan       `json:"action_plan,omitempty"`
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
	Handoff     *BundleHandoff   `json:"handoff,omitempty"`
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
	Type       string             `json:"type"`
	Value      string             `json:"value"`
	Context    string             `json:"context,omitempty"`
	Confidence float64            `json:"confidence,omitempty"`
	Handling   *BundleIOCHandling `json:"handling,omitempty"`
}

// BundleTTP matches the backend.
type BundleTTP struct {
	TacticID         string  `json:"tactic_id"`
	TacticName       string  `json:"tactic_name,omitempty"`
	TechniqueID      string  `json:"technique_id"`
	TechniqueName    string  `json:"technique_name,omitempty"`
	SubtechniqueID   string  `json:"subtechnique_id,omitempty"`
	SubtechniqueName string  `json:"subtechnique_name,omitempty"`
	Evidence         string  `json:"evidence,omitempty"`
	Confidence       float64 `json:"confidence,omitempty"`
	ConfidenceBand   string  `json:"confidence_band,omitempty"`
}

type BundleSourceAssessment struct {
	Reliability   string             `json:"reliability,omitempty"`
	Credibility   string             `json:"credibility,omitempty"`
	Rating        string             `json:"rating,omitempty"`
	Confidence    string             `json:"confidence,omitempty"`
	Likelihood    string             `json:"likelihood,omitempty"`
	Corroboration string             `json:"corroboration,omitempty"`
	Flags         []BundleSourceFlag `json:"flags,omitempty"`
	Gaps          []string           `json:"gaps,omitempty"`
}

type BundleSourceFlag struct {
	Type   string `json:"type,omitempty"`
	Detail string `json:"detail,omitempty"`
	Impact string `json:"impact,omitempty"`
}

type BundleQAStatus struct {
	Verdict            string   `json:"verdict,omitempty"`
	UnsupportedClaims  []string `json:"unsupported_claims,omitempty"`
	FormatGaps         []string `json:"format_gaps,omitempty"`
	TechnicalChecks    []string `json:"technical_checks,omitempty"`
	ManualVerification []string `json:"manual_verification,omitempty"`
	ValidationStatus   string   `json:"validation_status,omitempty"`
}

type BundleActionPlan struct {
	Priority         string                   `json:"priority,omitempty"`
	Owners           []string                 `json:"owners,omitempty"`
	ImmediateActions []BundleActionItem       `json:"immediate_actions,omitempty"`
	EnrichmentNeeded []BundleEnrichmentNeeded `json:"enrichment_needed,omitempty"`
	HuntLeads        []BundleHuntLead         `json:"hunt_leads,omitempty"`
	MitigationPlan   []BundleMitigation       `json:"mitigation_plan,omitempty"`
	Gaps             []string                 `json:"gaps,omitempty"`
}

type BundleActionItem struct {
	Action   string `json:"action,omitempty"`
	Owner    string `json:"owner,omitempty"`
	Due      string `json:"due,omitempty"`
	Evidence string `json:"evidence,omitempty"`
	Status   string `json:"status,omitempty"`
}

type BundleEnrichmentNeeded struct {
	Item     string `json:"item,omitempty"`
	Owner    string `json:"owner,omitempty"`
	Reason   string `json:"reason,omitempty"`
	Evidence string `json:"evidence,omitempty"`
}

type BundleHuntLead struct {
	Lead        string   `json:"lead,omitempty"`
	TechniqueID string   `json:"technique_id,omitempty"`
	DataNeeded  []string `json:"data_needed,omitempty"`
	Priority    string   `json:"priority,omitempty"`
	Confidence  string   `json:"confidence,omitempty"`
	Disposition string   `json:"disposition,omitempty"`
	Evidence    string   `json:"evidence,omitempty"`
}

type BundleMitigation struct {
	Priority  string `json:"priority,omitempty"`
	Action    string `json:"action,omitempty"`
	Owner     string `json:"owner,omitempty"`
	Addresses string `json:"addresses,omitempty"`
	Evidence  string `json:"evidence,omitempty"`
}

type BundleHandoff struct {
	DetectionConfidence string                      `json:"detection_confidence,omitempty"`
	RequiredTelemetry   []BundleRequiredTelemetry   `json:"required_telemetry,omitempty"`
	Validation          *BundleDetectionValidation  `json:"validation,omitempty"`
	KnownEvasions       []string                    `json:"known_evasions,omitempty"`
	Limitations         []string                    `json:"limitations,omitempty"`
	Tuning              []BundleFalsePositiveTuning `json:"tuning,omitempty"`
	PortabilityNotes    []BundlePortabilityNote     `json:"portability_notes,omitempty"`
	SuggestedOwner      string                      `json:"suggested_owner,omitempty"`
	Gaps                []string                    `json:"gaps,omitempty"`
}

type BundleRequiredTelemetry struct {
	LogSource      string   `json:"log_source,omitempty"`
	EventOrChannel string   `json:"event_or_channel,omitempty"`
	RequiredFields []string `json:"required_fields,omitempty"`
	Availability   string   `json:"availability,omitempty"`
	Notes          string   `json:"notes,omitempty"`
}

type BundleDetectionValidation struct {
	Status            string   `json:"status,omitempty"`
	Steps             []string `json:"steps,omitempty"`
	ExpectedTelemetry string   `json:"expected_telemetry,omitempty"`
	PassCriteria      string   `json:"pass_criteria,omitempty"`
	AtomicReference   string   `json:"atomic_reference,omitempty"`
}

type BundleFalsePositiveTuning struct {
	Source   string `json:"source,omitempty"`
	Guidance string `json:"guidance,omitempty"`
}

type BundlePortabilityNote struct {
	Platform string `json:"platform,omitempty"`
	Note     string `json:"note,omitempty"`
}

type BundleIOCHandling struct {
	RecommendedAction  string   `json:"recommended_action,omitempty"`
	Priority           string   `json:"priority,omitempty"`
	SourceSentence     string   `json:"source_sentence,omitempty"`
	SourceName         string   `json:"source_name,omitempty"`
	SourceURL          string   `json:"source_url,omitempty"`
	AssociatedThreats  []string `json:"associated_threats,omitempty"`
	EnrichmentStatus   string   `json:"enrichment_status,omitempty"`
	LogSources         []string `json:"log_sources,omitempty"`
	EnvironmentTags    []string `json:"environment_tags,omitempty"`
	DetectionNotes     string   `json:"detection_notes,omitempty"`
	FalsePositiveNotes string   `json:"false_positive_notes,omitempty"`
}

// Enumerated values used to validate YAML brief source files. Keep these in
// sync with the public feed schema and the notifier/email templates.
var (
	validBriefSeverities = map[string]bool{
		"critical":      true,
		"high":          true,
		"medium":        true,
		"low":           true,
		"rumour":        true,
		"informational": true,
	}
	validBriefTypes = map[string]bool{
		"threat":   true,
		"coverage": true,
		"advisory": true,
		"rumour":   true,
	}
	validRuleSeverities = map[string]bool{
		"critical":      true,
		"high":          true,
		"medium":        true,
		"low":           true,
		"informational": true,
	}
	validRulePlatforms = map[string]bool{
		"sigma":    true,
		"spl":      true,
		"kql":      true,
		"eql":      true,
		"fql":      true,
		"leql":     true,
		"falconql": true,
	}
)

// LoadBriefs reads all YAML files from the given directory. It reports every
// parse and validation error it finds rather than stopping at the first one.
func LoadBriefs(dir string) ([]Brief, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading briefs directory: %w", err)
	}

	var briefs []Brief
	var errs []error
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
			errs = append(errs, fmt.Errorf("reading %s: %w", path, err))
			continue
		}

		var b Brief
		if err := yaml.Unmarshal(data, &b); err != nil {
			errs = append(errs, fmt.Errorf("parsing %s: %w", path, err))
			continue
		}

		if verrs := validateBrief(&b, name); len(verrs) > 0 {
			errs = append(errs, verrs...)
			continue
		}

		briefs = append(briefs, b)
	}

	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}

	// Sort by published_at descending for deterministic output
	sort.Slice(briefs, func(i, j int) bool {
		return briefs[i].PublishedAt > briefs[j].PublishedAt
	})

	return briefs, nil
}

func validateBrief(b *Brief, filename string) []error {
	var errs []error
	if b.ID == "" {
		errs = append(errs, fmt.Errorf("%s: missing required field 'id'", filename))
	}
	if b.Slug == "" {
		errs = append(errs, fmt.Errorf("%s: missing required field 'slug'", filename))
	}
	if b.Title == "" {
		errs = append(errs, fmt.Errorf("%s: missing required field 'title'", filename))
	}
	if b.Summary == "" {
		errs = append(errs, fmt.Errorf("%s: missing required field 'summary'", filename))
	}
	if b.Severity == "" {
		errs = append(errs, fmt.Errorf("%s: missing required field 'severity'", filename))
	} else if !validBriefSeverities[strings.ToLower(b.Severity)] {
		errs = append(errs, fmt.Errorf("%s: invalid severity %q", filename, b.Severity))
	}
	if b.Type != "" && !validBriefTypes[strings.ToLower(b.Type)] {
		errs = append(errs, fmt.Errorf("%s: invalid type %q", filename, b.Type))
	}
	if b.PublishedAt == "" {
		errs = append(errs, fmt.Errorf("%s: missing required field 'published_at'", filename))
	}
	for i, r := range b.Rules {
		if r.Title == "" {
			errs = append(errs, fmt.Errorf("%s: rule[%d]: missing title", filename, i))
			continue
		}
		if r.Query == "" {
			errs = append(errs, fmt.Errorf("%s: rule[%d] %q: missing query", filename, i, r.Title))
		}
		if r.Platform == "" {
			errs = append(errs, fmt.Errorf("%s: rule[%d] %q: missing platform", filename, i, r.Title))
		} else if !validRulePlatforms[strings.ToLower(r.Platform)] {
			errs = append(errs, fmt.Errorf("%s: rule[%d] %q: invalid platform %q", filename, i, r.Title, r.Platform))
		}
		if r.Severity != "" && !validRuleSeverities[strings.ToLower(r.Severity)] {
			errs = append(errs, fmt.Errorf("%s: rule[%d] %q: invalid severity %q", filename, i, r.Title, r.Severity))
		}
	}
	for i, ind := range b.IOCs {
		if !ioc.KnownTypes[strings.ToLower(ind.Type)] {
			errs = append(errs, fmt.Errorf("%s: ioc[%d]: unknown type %q", filename, i, ind.Type))
		} else if err := ioc.Validate(ind.Type, ind.Value); err != nil {
			errs = append(errs, fmt.Errorf("%s: ioc[%d]: invalid %s: %w", filename, i, ind.Type, err))
		}
	}
	if err := ValidateBriefTTPs(*b); err != nil {
		errs = append(errs, fmt.Errorf("%s: %w", filename, err))
	}
	return errs
}

// ValidateBriefTTPs returns an error if any TTP references a tactic,
// technique, or sub-technique ID not in the ATT&CK catalog. Gives
// human-authored briefs the same ID check ti-bot's automated path enforces.
func ValidateBriefTTPs(b Brief) error {
	for i, ttp := range b.TTPs {
		if ttp.TacticID != "" && !mitre.ValidTactic(ttp.TacticID) {
			return fmt.Errorf("brief %q ttp #%d: invalid tactic_id %q", b.ID, i, ttp.TacticID)
		}
		if !mitre.ValidTechnique(ttp.TechniqueID) {
			return fmt.Errorf("brief %q ttp #%d: invalid technique_id %q", b.ID, i, ttp.TechniqueID)
		}
		if ttp.SubtechniqueID != "" && !mitre.ValidTechnique(ttp.SubtechniqueID) {
			return fmt.Errorf("brief %q ttp #%d: invalid subtechnique_id %q", b.ID, i, ttp.SubtechniqueID)
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
			ID:               b.ID,
			Slug:             b.Slug,
			Title:            b.Title,
			Summary:          b.Summary,
			Content:          b.Content,
			Type:             b.Type,
			Severity:         b.Severity,
			ThreatActor:      b.ThreatActor,
			PublishedAt:      b.PublishedAt,
			Tags:             b.Tags,
			References:       b.References,
			SourceAssessment: cloneBundleMetadata[BundleSourceAssessment](b.SourceAssessment),
			QAStatus:         cloneBundleMetadata[BundleQAStatus](b.QAStatus),
			ActionPlan:       cloneBundleMetadata[BundleActionPlan](b.ActionPlan),
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
				Handoff:     cloneBundleMetadata[BundleHandoff](r.Handoff),
			}
			if r.Tests != nil {
				br.Tests = &BundleTestSuite{}
				for _, tc := range r.Tests.Positive {
					br.Tests.Positive = append(br.Tests.Positive, BundleTestCase(tc))
				}
				for _, tc := range r.Tests.Negative {
					br.Tests.Negative = append(br.Tests.Negative, BundleTestCase(tc))
				}
			}
			bb.Rules = append(bb.Rules, br)
		}
		for _, ioc := range b.IOCs {
			bb.IOCs = append(bb.IOCs, BundleIOC{
				Type:       ioc.Type,
				Value:      ioc.Value,
				Context:    ioc.Context,
				Confidence: ioc.Confidence,
				Handling:   cloneBundleMetadata[BundleIOCHandling](ioc.Handling),
			})
		}
		for _, ttp := range b.TTPs {
			bb.TTPs = append(bb.TTPs, BundleTTP(ttp))
		}
		content.Briefs = append(content.Briefs, bb)
	}
	return content
}

func cloneBundleMetadata[T any](in any) *T {
	if in == nil {
		return nil
	}
	data, err := json.Marshal(in)
	if err != nil {
		return nil
	}
	var out T
	if err := json.Unmarshal(data, &out); err != nil {
		return nil
	}
	return &out
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

// EncryptDigest encrypts a single BundleDigest into a BundleManifest using AES-256-GCM.
func EncryptDigest(digest *BundleDigest, publishedAt, publicKeyHex string) (*BundleManifest, error) {
	key, err := DeriveKey(publicKeyHex)
	if err != nil {
		return nil, err
	}

	plaintext, err := json.Marshal(digest)
	if err != nil {
		return nil, fmt.Errorf("marshaling digest: %w", err)
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
		Version:     "1.0",
		PublishedAt: publishedAt,
		Checksum:    checksum,
		Content:     base64.StdEncoding.EncodeToString(ciphertext),
	}, nil
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
