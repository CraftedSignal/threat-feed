package main

import (
	"fmt"
	"strings"
	"testing"
)

func TestFilterMatchesCanonicalVendorAndVersionedProduct(t *testing.T) {
	filter := Filter{
		Vendors:  []string{"Synology Inc."},
		Products: []string{"Synology Chat Server (< 2.4.5-22148)"},
	}
	brief := Brief{
		Vendors:  []string{"Synology"},
		Products: []string{"Synology Chat Server (2.4.4)"},
	}
	if !filter.Matches(brief) {
		t.Fatal("canonical vendor and product names should match across suffixes and version qualifiers")
	}

	filter.Vendors = []string{"Synology"}
	brief.Vendors = []string{"Synology Inc."}
	if !filter.Matches(brief) {
		t.Fatal("new and stored subscription vendor names should both be canonicalized")
	}
}

func TestFilterMatchesTiBotAliases(t *testing.T) {
	filter := Filter{Vendors: []string{"Flowise AI"}, Products: []string{"Flowise CSV Agent"}}
	brief := Brief{Vendors: []string{"Flowise"}, Products: []string{"Flowise"}}
	if !filter.Matches(brief) {
		t.Fatal("ti-bot canonical vendor/product aliases should match")
	}
}

func TestFilterPreservesNumericProductModelAndMatchesDSMAlias(t *testing.T) {
	if normalizeProduct("RTX 5090") != "rtx5090" {
		t.Fatal("numeric model suffix should be preserved")
	}
	if normalizeProduct("RTX 5090") == normalizeProduct("RTX 4090") {
		t.Fatal("different numeric product models must not canonicalize together")
	}
	if !(Filter{Products: []string{"DSM"}}).Matches(Brief{Products: []string{"DiskStation Manager (< 7.4.1-90080-1)"}}) {
		t.Fatal("DSM subscription should match DiskStation Manager product reports")
	}
}

func TestFilterHasPOCRequiresBriefPoC(t *testing.T) {
	filter := Filter{HasPOC: true}
	if filter.Matches(Brief{}) {
		t.Fatal("PoC-only filter matched a brief without public PoC")
	}
	if !filter.Matches(Brief{HasPOC: true}) {
		t.Fatal("PoC-only filter did not match a brief with public PoC")
	}
}

func TestSubscribeRequestBoundsVendorAndProductFilters(t *testing.T) {
	tooMany := make([]string, 33)
	for i := range tooMany {
		tooMany[i] = fmt.Sprintf("Vendor %d", i)
	}
	for name, filter := range map[string]Filter{
		"vendor count":   {Vendors: tooMany},
		"product count":  {Products: tooMany},
		"vendor length":  {Vendors: []string{strings.Repeat("v", 121)}},
		"product length": {Products: []string{strings.Repeat("p", 121)}},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := (subscribeRequest{Channel: "email", Email: "reader@example.com", Filter: filter}).toSubscription()
			if err == nil {
				t.Fatal("expected an invalid vendor/product filter to be rejected")
			}
		})
	}
}
