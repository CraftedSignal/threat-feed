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
	Severity    string   `yaml:"severity"`
	ThreatActor string   `yaml:"threat_actor"`
	PublishedAt string   `yaml:"published_at"`
	Tags        []string `yaml:"tags"`
	References  []string `yaml:"references"`
	Rules       []Rule   `yaml:"rules"`
	IOCs        []IOC    `yaml:"iocs"`
	TTPs        []TTP    `yaml:"ttps"`
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
	Type    string `yaml:"type"`
	Value   string `yaml:"value"`
	Context string `yaml:"context"`
}

// TTP is a MITRE ATT&CK technique.
type TTP struct {
	TacticID         string `yaml:"tactic_id"`
	TacticName       string `yaml:"tactic_name"`
	TechniqueID      string `yaml:"technique_id"`
	TechniqueName    string `yaml:"technique_name"`
	SubtechniqueID   string `yaml:"subtechnique_id"`
	SubtechniqueName string `yaml:"subtechnique_name"`
}
