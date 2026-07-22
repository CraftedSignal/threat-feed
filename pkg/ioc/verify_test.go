package ioc

import "testing"

func TestValidate_Valid(t *testing.T) {
	cases := []struct {
		typ, value string
	}{
		{TypeSHA256, "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"},
		{TypeMD5, "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"},
		{TypeSHA1, "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"},
		{TypeIP, "8.8.8.8"},
		{TypeIPv4, "1.1.1.1"},
		{TypeDomain, "evil.example.co"},
		{TypeEmail, "attacker@evil.example.co"},
		{TypeURL, "https://evil.example.co/payload"},
	}
	for _, tc := range cases {
		if err := Validate(tc.typ, tc.value); err != nil {
			t.Errorf("Validate(%q, %q): unexpected error: %v", tc.typ, tc.value, err)
		}
	}
}

func TestValidate_Invalid(t *testing.T) {
	cases := []struct {
		typ, value, wantErr string
	}{
		{TypeSHA256, "tooshort", "64 hex chars"},
		{TypeMD5, "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", "non-hex"},
		{TypeSHA1, "abc123", "40 hex chars"},
		{TypeIP, "192.168.1.1", "private"},
		{TypeIP, "127.0.0.1", "loopback"},
		{TypeIP, "192.0.2.1", "documentation"},
		{TypeDomain, "localhost", "dot"},
		{TypeDomain, "8.8.8.8", "IP address"},
		{TypeDomain, "evil.x", "TLD"},
		{TypeEmail, "[email&#160;protected]", "HTML"},
		{TypeEmail, "no-at-sign", "@"},
		{TypeURL, "ftp://evil.com/payload", "http"},
		{"unknown", "anything", ""}, // unknown types are accepted
	}
	for _, tc := range cases {
		err := Validate(tc.typ, tc.value)
		if tc.wantErr == "" {
			if err != nil {
				t.Errorf("Validate(%q, %q): unexpected error: %v", tc.typ, tc.value, err)
			}
			continue
		}
		if err == nil {
			t.Errorf("Validate(%q, %q): expected error containing %q", tc.typ, tc.value, tc.wantErr)
			continue
		}
		if !contains(err.Error(), tc.wantErr) {
			t.Errorf("Validate(%q, %q): error %q does not contain %q", tc.typ, tc.value, err.Error(), tc.wantErr)
		}
	}
}

func TestKnownTypes(t *testing.T) {
	for _, typ := range []string{TypeSHA256, TypeMD5, TypeSHA1, TypeIP, TypeIPv4, TypeDomain, TypeEmail, TypeURL} {
		if !KnownTypes[typ] {
			t.Errorf("KnownTypes missing %q", typ)
		}
	}
	if KnownTypes["unknown"] {
		t.Error("KnownTypes should not contain 'unknown'")
	}
}

func contains(s, substr string) bool {
	return len(substr) <= len(s) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
