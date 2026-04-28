package main

import "strings"

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
	if len(f.Actors) > 0 && !anyContainsFold(f.Actors, b.Actors) {
		return false
	}
	if len(f.Vendors) > 0 && !anyContainsFold(f.Vendors, b.Vendors) {
		return false
	}
	if len(f.Products) > 0 && !anyContainsFold(f.Products, b.Products) {
		return false
	}
	if len(f.Tags) > 0 && !anyContainsFold(f.Tags, b.Tags) {
		return false
	}
	return true
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
