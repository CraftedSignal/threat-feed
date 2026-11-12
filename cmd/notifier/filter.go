package main

import (
	"regexp"
	"strings"
)

var (
	versionQualifier = regexp.MustCompile(`\s*\((?:(?:[<>=~^]+\s*)?\d+(?:[.-]\d+)+(?:[-+][\w.-]+)?|v(?:ersion)?\s*\d[\w.+-]*)\)\s*$`)
	nonAlphaNumeric  = regexp.MustCompile(`[^a-z0-9]+`)
	corporateSuffix  = regexp.MustCompile(`\b(inc\.?|ltd\.?|limited|corp\.?|corporation|llc|plc|ag|gmbh|s\.a\.?|b\.v\.?|s\.l\.?|k\.k\.?|co\.?)\b`)
)

var vendorAliases = map[string]string{"flowiseai": "flowise"}
var productAliases = map[string]string{
	"flowiseai":        "flowise",
	"flowiseaiflowise": "flowise",
	"flowisecsvagent":  "flowise",
	"dsm":              "diskstationmanager",
}

// Matches reports whether a brief satisfies all populated filter fields.
// Empty slice on a field = no constraint. Match is case-insensitive.
func (f Filter) Matches(b Brief) bool {
	if len(f.Types) > 0 && !containsFold(f.Types, b.Type) {
		return false
	}
	if len(f.Severities) > 0 && !containsFold(f.Severities, b.Severity) {
		return false
	}
	if f.Exploited && !b.Exploited {
		return false
	}
	if f.HasPOC && !b.HasPOC {
		return false
	}
	if len(f.Actors) > 0 && !anyContainsFold(f.Actors, b.Actors) {
		return false
	}
	if len(f.Vendors) > 0 && !anyCanonicalOverlap(f.Vendors, b.Vendors, normalizeVendor) {
		return false
	}
	if len(f.Products) > 0 && !anyCanonicalOverlap(f.Products, b.Products, normalizeProduct) {
		return false
	}
	if len(f.Tags) > 0 && !anyContainsFold(f.Tags, b.Tags) {
		return false
	}
	return true
}

func normalizeVendor(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = corporateSuffix.ReplaceAllString(value, " ")
	value = nonAlphaNumeric.ReplaceAllString(value, "")
	if alias, ok := vendorAliases[value]; ok {
		return alias
	}
	return value
}

func normalizeProduct(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = versionQualifier.ReplaceAllString(value, "")
	value = nonAlphaNumeric.ReplaceAllString(value, "")
	if alias, ok := productAliases[value]; ok {
		return alias
	}
	return value
}

func anyCanonicalOverlap(needles, values []string, normalize func(string) string) bool {
	set := make(map[string]struct{}, len(needles))
	for _, value := range needles {
		if key := normalize(value); key != "" {
			set[key] = struct{}{}
		}
	}
	for _, value := range values {
		if _, ok := set[normalize(value)]; ok && normalize(value) != "" {
			return true
		}
	}
	return false
}

func containsFold(needles []string, haystack string) bool {
	for _, n := range needles {
		if strings.EqualFold(n, haystack) {
			return true
		}
	}
	return false
}

func anyContainsFold(needles, haystack []string) bool {
	for _, h := range haystack {
		if containsFold(needles, h) {
			return true
		}
	}
	return false
}
