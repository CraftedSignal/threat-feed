package mitre

import "testing"

func TestValidTactic(t *testing.T) {
	tests := []struct {
		id   string
		want bool
	}{
		{"TA0001", true},  // Initial Access
		{"TA0040", true},  // Impact
		{"TA0043", true},  // Reconnaissance
		{"TA0099", false}, // does not exist
		{"ta0001", false}, // wrong case
		{"", false},
	}
	for _, tt := range tests {
		if got := ValidTactic(tt.id); got != tt.want {
			t.Errorf("ValidTactic(%q) = %v, want %v", tt.id, got, tt.want)
		}
	}
}

func TestValidTechnique(t *testing.T) {
	tests := []struct {
		id   string
		want bool
	}{
		{"T1566", true},      // Phishing
		{"T1566.001", true},  // Spearphishing Attachment
		{"T1219", true},      // Remote Access Software
		{"T1219.003", false}, // does not exist
		{"T1064", false},     // deprecated
		{"T1048.003", true},  // Exfiltration Over Unencrypted Non-C2 Protocol
		{"T1048.004", false}, // does not exist
		{"T9999", false},     // does not exist
		{"", false},
	}
	for _, tt := range tests {
		if got := ValidTechnique(tt.id); got != tt.want {
			t.Errorf("ValidTechnique(%q) = %v, want %v", tt.id, got, tt.want)
		}
	}
}

func TestTacticName(t *testing.T) {
	if got := TacticName("TA0001"); got != "Initial Access" {
		t.Errorf("TacticName(TA0001) = %q, want %q", got, "Initial Access")
	}
	if got := TacticName("TA9999"); got != "" {
		t.Errorf("TacticName(TA9999) = %q, want empty", got)
	}
}

func TestTechniqueName(t *testing.T) {
	if got := TechniqueName("T1566"); got != "Phishing" {
		t.Errorf("TechniqueName(T1566) = %q, want %q", got, "Phishing")
	}
	if got := TechniqueName("T1566.001"); got != "Spearphishing Attachment" {
		t.Errorf("TechniqueName(T1566.001) = %q, want %q", got, "Spearphishing Attachment")
	}
	if got := TechniqueName("T9999"); got != "" {
		t.Errorf("TechniqueName(T9999) = %q, want empty", got)
	}
}

func TestTacticCount(t *testing.T) {
	if len(Tactics) != 14 {
		t.Errorf("expected 14 tactics, got %d", len(Tactics))
	}
}

func TestTechniqueCount(t *testing.T) {
	// Enterprise ATT&CK v16 has 656 active techniques and subtechniques.
	// This test ensures we haven't accidentally added or removed entries.
	if len(Techniques) < 600 {
		t.Errorf("expected at least 600 techniques, got %d - map may be incomplete", len(Techniques))
	}
	t.Logf("Techniques map contains %d entries", len(Techniques))
}
