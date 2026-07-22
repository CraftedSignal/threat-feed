// Package ioc validates indicator-of-compromise values across CraftedSignal
// projects. It rejects malformed, private, or placeholder indicators.
package ioc

import (
	"fmt"
	"net"
	"regexp"
	"strings"
)

const (
	TypeSHA256 = "hash_sha256"
	TypeMD5    = "hash_md5"
	TypeSHA1   = "hash_sha1"
	TypeIP     = "ip"
	TypeIPv4   = "ipv4"
	TypeDomain = "domain"
	TypeEmail  = "email"
	TypeURL    = "url"
)

// KnownTypes is the set of IOC types supported by Validate.
var KnownTypes = map[string]bool{
	TypeSHA256: true,
	TypeMD5:    true,
	TypeSHA1:   true,
	TypeIP:     true,
	TypeIPv4:   true,
	TypeDomain: true,
	TypeEmail:  true,
	TypeURL:    true,
}

// hexRe matches a string containing only hex characters.
var hexRe = regexp.MustCompile(`^[0-9a-fA-F]+$`)

// Validate checks whether an IOC value matches the expected format for its
// type. It returns nil if valid, or an error describing the problem otherwise.
// Unknown types are accepted without format checks so that new indicator kinds
// do not break the pipeline, but callers can use KnownTypes to reject them if
// desired.
func Validate(typ, value string) error {
	val := strings.TrimSpace(value)
	if val == "" {
		return fmt.Errorf("empty value")
	}

	switch strings.ToLower(typ) {
	case TypeSHA256:
		if len(val) != 64 {
			return fmt.Errorf("SHA-256 hash must be exactly 64 hex chars, got %d", len(val))
		}
		if !hexRe.MatchString(val) {
			return fmt.Errorf("SHA-256 hash contains non-hex characters")
		}

	case TypeMD5:
		if len(val) != 32 {
			return fmt.Errorf("MD5 hash must be exactly 32 hex chars, got %d", len(val))
		}
		if !hexRe.MatchString(val) {
			return fmt.Errorf("MD5 hash contains non-hex characters")
		}

	case TypeSHA1:
		if len(val) != 40 {
			return fmt.Errorf("SHA-1 hash must be exactly 40 hex chars, got %d", len(val))
		}
		if !hexRe.MatchString(val) {
			return fmt.Errorf("SHA-1 hash contains non-hex characters")
		}

	case TypeIP, TypeIPv4:
		ip := net.ParseIP(val)
		if ip == nil {
			return fmt.Errorf("not a valid IP address")
		}
		ip4 := ip.To4()
		if ip4 == nil {
			return fmt.Errorf("not a valid IPv4 address")
		}
		if ip.IsLoopback() {
			return fmt.Errorf("loopback address")
		}
		if ip.IsPrivate() {
			return fmt.Errorf("private address")
		}
		if isDocumentationIP(ip4) {
			return fmt.Errorf("documentation range address")
		}

	case TypeDomain:
		if net.ParseIP(val) != nil {
			return fmt.Errorf("domain value is an IP address")
		}
		if !strings.Contains(val, ".") {
			return fmt.Errorf("domain must contain at least one dot")
		}
		parts := strings.Split(val, ".")
		tld := parts[len(parts)-1]
		if len(tld) < 2 {
			return fmt.Errorf("TLD %q is too short (must be at least 2 chars)", tld)
		}

	case TypeEmail:
		// Reject HTML-entity-obfuscated addresses (Cloudflare "[email&#160;protected]"
		// pattern, &amp; escapes, etc.) — these are scraper-protection artifacts,
		// not real indicators.
		if strings.Contains(val, "&#") || strings.Contains(val, "&amp;") || strings.Contains(val, "[email") {
			return fmt.Errorf("email value contains HTML entities or obfuscation placeholder")
		}
		at := strings.Index(val, "@")
		if at < 1 {
			return fmt.Errorf("email must contain '@' with a non-empty local part")
		}
		domain := val[at+1:]
		if !strings.Contains(domain, ".") || strings.HasSuffix(domain, ".") {
			return fmt.Errorf("email domain %q is not valid", domain)
		}

	case TypeURL:
		if !strings.HasPrefix(val, "http://") && !strings.HasPrefix(val, "https://") {
			return fmt.Errorf("URL must start with http:// or https://")
		}

	default:
		// Unknown type: do not enforce a format. Callers that need strict typing
		// can check KnownTypes first.
	}

	return nil
}

// isDocumentationIP checks if an IPv4 address falls in documentation ranges
// (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24).
func isDocumentationIP(ip net.IP) bool {
	docRanges := []struct {
		prefix net.IP
		mask   net.IPMask
	}{
		{net.IP{192, 0, 2, 0}, net.CIDRMask(24, 32)},
		{net.IP{198, 51, 100, 0}, net.CIDRMask(24, 32)},
		{net.IP{203, 0, 113, 0}, net.CIDRMask(24, 32)},
	}
	for _, r := range docRanges {
		network := &net.IPNet{IP: r.prefix, Mask: r.mask}
		if network.Contains(ip) {
			return true
		}
	}
	return false
}
