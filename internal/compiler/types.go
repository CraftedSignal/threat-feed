// Package compiler reads YAML threat brief source files and compiles them
// into an encrypted feed bundle.
package compiler

// Brief is the YAML source format for a single threat intelligence brief.
type Brief struct {
	ID          string   `yaml:"id"`
	Slug        string   `yaml:"slug"`
	Title       string   `yaml:"title"`
	Summary     string   `yaml:"summary"`
	Content     string   `yaml:"content"`
	Type        string   `yaml:"type"`
	Severity    string   `yaml:"severity"`
	ThreatActor string   `yaml:"threat_actor"`
	PublishedAt string   `yaml:"published_at"`
	Tags        []string `yaml:"tags"`
	References  []string `yaml:"references"`
	Rules       []Rule   `yaml:"rules"`
	IOCs        []IOC    `yaml:"iocs"`
	TTPs        []TTP    `yaml:"ttps"`

	SourceAssessment *SourceAssessment `yaml:"source_assessment,omitempty"`
	QAStatus         *QAStatus         `yaml:"qa_status,omitempty"`
	ActionPlan       *ActionPlan       `yaml:"action_plan,omitempty"`
}

// Rule is a detection rule within a brief.
type Rule struct {
	Title       string    `yaml:"title"`
	Description string    `yaml:"description"`
	Query       string    `yaml:"query"`
	Platform    string    `yaml:"platform"`
	Severity    string    `yaml:"severity"`
	Tactics     []string  `yaml:"tactics"`
	Techniques  []string  `yaml:"techniques"`
	DataSources []string  `yaml:"data_sources"`
	Tests       *TestData `yaml:"tests"`
	Handoff     *Handoff  `yaml:"handoff,omitempty"`
}

// TestData contains positive and negative test cases.
type TestData struct {
	Positive []TestCase `yaml:"positive"`
	Negative []TestCase `yaml:"negative"`
}

// TestCase is a single test case with sample log data.
type TestCase struct {
	Name        string                   `yaml:"name"`
	Description string                   `yaml:"description"`
	Data        []map[string]interface{} `yaml:"data"`
}

// IOC is an indicator of compromise.
type IOC struct {
	Type       string       `yaml:"type"`
	Value      string       `yaml:"value"`
	Context    string       `yaml:"context"`
	Confidence float64      `yaml:"confidence,omitempty"`
	Handling   *IOCHandling `yaml:"handling,omitempty"`
}

// TTP is a MITRE ATT&CK technique.
type TTP struct {
	TacticID         string  `yaml:"tactic_id"`
	TacticName       string  `yaml:"tactic_name"`
	TechniqueID      string  `yaml:"technique_id"`
	TechniqueName    string  `yaml:"technique_name"`
	SubtechniqueID   string  `yaml:"subtechnique_id"`
	SubtechniqueName string  `yaml:"subtechnique_name"`
	Evidence         string  `yaml:"evidence,omitempty"`
	Confidence       float64 `yaml:"confidence,omitempty"`
	ConfidenceBand   string  `yaml:"confidence_band,omitempty"`
}

type SourceAssessment struct {
	Reliability   string       `yaml:"reliability,omitempty" json:"reliability,omitempty"`
	Credibility   string       `yaml:"credibility,omitempty" json:"credibility,omitempty"`
	Rating        string       `yaml:"rating,omitempty" json:"rating,omitempty"`
	Confidence    string       `yaml:"confidence,omitempty" json:"confidence,omitempty"`
	Likelihood    string       `yaml:"likelihood,omitempty" json:"likelihood,omitempty"`
	Corroboration string       `yaml:"corroboration,omitempty" json:"corroboration,omitempty"`
	Flags         []SourceFlag `yaml:"flags,omitempty" json:"flags,omitempty"`
	Gaps          []string     `yaml:"gaps,omitempty" json:"gaps,omitempty"`
}

type SourceFlag struct {
	Type   string `yaml:"type,omitempty" json:"type,omitempty"`
	Detail string `yaml:"detail,omitempty" json:"detail,omitempty"`
	Impact string `yaml:"impact,omitempty" json:"impact,omitempty"`
}

type QAStatus struct {
	Verdict            string   `yaml:"verdict,omitempty" json:"verdict,omitempty"`
	UnsupportedClaims  []string `yaml:"unsupported_claims,omitempty" json:"unsupported_claims,omitempty"`
	FormatGaps         []string `yaml:"format_gaps,omitempty" json:"format_gaps,omitempty"`
	TechnicalChecks    []string `yaml:"technical_checks,omitempty" json:"technical_checks,omitempty"`
	ManualVerification []string `yaml:"manual_verification,omitempty" json:"manual_verification,omitempty"`
	ValidationStatus   string   `yaml:"validation_status,omitempty" json:"validation_status,omitempty"`
}

type ActionPlan struct {
	Priority         string             `yaml:"priority,omitempty" json:"priority,omitempty"`
	Owners           []string           `yaml:"owners,omitempty" json:"owners,omitempty"`
	ImmediateActions []ActionItem       `yaml:"immediate_actions,omitempty" json:"immediate_actions,omitempty"`
	EnrichmentNeeded []EnrichmentNeeded `yaml:"enrichment_needed,omitempty" json:"enrichment_needed,omitempty"`
	HuntLeads        []HuntLead         `yaml:"hunt_leads,omitempty" json:"hunt_leads,omitempty"`
	MitigationPlan   []Mitigation       `yaml:"mitigation_plan,omitempty" json:"mitigation_plan,omitempty"`
	Gaps             []string           `yaml:"gaps,omitempty" json:"gaps,omitempty"`
}

type ActionItem struct {
	Action   string `yaml:"action,omitempty" json:"action,omitempty"`
	Owner    string `yaml:"owner,omitempty" json:"owner,omitempty"`
	Due      string `yaml:"due,omitempty" json:"due,omitempty"`
	Evidence string `yaml:"evidence,omitempty" json:"evidence,omitempty"`
	Status   string `yaml:"status,omitempty" json:"status,omitempty"`
}

type EnrichmentNeeded struct {
	Item     string `yaml:"item,omitempty" json:"item,omitempty"`
	Owner    string `yaml:"owner,omitempty" json:"owner,omitempty"`
	Reason   string `yaml:"reason,omitempty" json:"reason,omitempty"`
	Evidence string `yaml:"evidence,omitempty" json:"evidence,omitempty"`
}

type HuntLead struct {
	Lead        string   `yaml:"lead,omitempty" json:"lead,omitempty"`
	TechniqueID string   `yaml:"technique_id,omitempty" json:"technique_id,omitempty"`
	DataNeeded  []string `yaml:"data_needed,omitempty" json:"data_needed,omitempty"`
	Priority    string   `yaml:"priority,omitempty" json:"priority,omitempty"`
	Confidence  string   `yaml:"confidence,omitempty" json:"confidence,omitempty"`
	Disposition string   `yaml:"disposition,omitempty" json:"disposition,omitempty"`
	Evidence    string   `yaml:"evidence,omitempty" json:"evidence,omitempty"`
}

type Mitigation struct {
	Priority  string `yaml:"priority,omitempty" json:"priority,omitempty"`
	Action    string `yaml:"action,omitempty" json:"action,omitempty"`
	Owner     string `yaml:"owner,omitempty" json:"owner,omitempty"`
	Addresses string `yaml:"addresses,omitempty" json:"addresses,omitempty"`
	Evidence  string `yaml:"evidence,omitempty" json:"evidence,omitempty"`
}

type Handoff struct {
	DetectionConfidence string                `yaml:"detection_confidence,omitempty" json:"detection_confidence,omitempty"`
	RequiredTelemetry   []RequiredTelemetry   `yaml:"required_telemetry,omitempty" json:"required_telemetry,omitempty"`
	Validation          *DetectionValidation  `yaml:"validation,omitempty" json:"validation,omitempty"`
	KnownEvasions       []string              `yaml:"known_evasions,omitempty" json:"known_evasions,omitempty"`
	Limitations         []string              `yaml:"limitations,omitempty" json:"limitations,omitempty"`
	Tuning              []FalsePositiveTuning `yaml:"tuning,omitempty" json:"tuning,omitempty"`
	PortabilityNotes    []PortabilityNote     `yaml:"portability_notes,omitempty" json:"portability_notes,omitempty"`
	SuggestedOwner      string                `yaml:"suggested_owner,omitempty" json:"suggested_owner,omitempty"`
	Gaps                []string              `yaml:"gaps,omitempty" json:"gaps,omitempty"`
}

type RequiredTelemetry struct {
	LogSource      string   `yaml:"log_source,omitempty" json:"log_source,omitempty"`
	EventOrChannel string   `yaml:"event_or_channel,omitempty" json:"event_or_channel,omitempty"`
	RequiredFields []string `yaml:"required_fields,omitempty" json:"required_fields,omitempty"`
	Availability   string   `yaml:"availability,omitempty" json:"availability,omitempty"`
	Notes          string   `yaml:"notes,omitempty" json:"notes,omitempty"`
}

type DetectionValidation struct {
	Status            string   `yaml:"status,omitempty" json:"status,omitempty"`
	Steps             []string `yaml:"steps,omitempty" json:"steps,omitempty"`
	ExpectedTelemetry string   `yaml:"expected_telemetry,omitempty" json:"expected_telemetry,omitempty"`
	PassCriteria      string   `yaml:"pass_criteria,omitempty" json:"pass_criteria,omitempty"`
	AtomicReference   string   `yaml:"atomic_reference,omitempty" json:"atomic_reference,omitempty"`
}

type FalsePositiveTuning struct {
	Source   string `yaml:"source,omitempty" json:"source,omitempty"`
	Guidance string `yaml:"guidance,omitempty" json:"guidance,omitempty"`
}

type PortabilityNote struct {
	Platform string `yaml:"platform,omitempty" json:"platform,omitempty"`
	Note     string `yaml:"note,omitempty" json:"note,omitempty"`
}

type IOCHandling struct {
	RecommendedAction  string   `yaml:"recommended_action,omitempty" json:"recommended_action,omitempty"`
	Priority           string   `yaml:"priority,omitempty" json:"priority,omitempty"`
	SourceSentence     string   `yaml:"source_sentence,omitempty" json:"source_sentence,omitempty"`
	SourceName         string   `yaml:"source_name,omitempty" json:"source_name,omitempty"`
	SourceURL          string   `yaml:"source_url,omitempty" json:"source_url,omitempty"`
	AssociatedThreats  []string `yaml:"associated_threats,omitempty" json:"associated_threats,omitempty"`
	EnrichmentStatus   string   `yaml:"enrichment_status,omitempty" json:"enrichment_status,omitempty"`
	LogSources         []string `yaml:"log_sources,omitempty" json:"log_sources,omitempty"`
	EnvironmentTags    []string `yaml:"environment_tags,omitempty" json:"environment_tags,omitempty"`
	DetectionNotes     string   `yaml:"detection_notes,omitempty" json:"detection_notes,omitempty"`
	FalsePositiveNotes string   `yaml:"false_positive_notes,omitempty" json:"false_positive_notes,omitempty"`
}
