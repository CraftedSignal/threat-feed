// Package mitre re-exports the shared MITRE ATT&CK catalog from
// github.com/craftedsignal/common/pkg/mitre so the threat-feed compiler can
// keep using the same local import path.
package mitre

import "github.com/craftedsignal/threat-feed/pkg/mitre"

// Tactics maps Enterprise ATT&CK tactic IDs to their canonical names.
var Tactics = mitre.Tactics

// Techniques maps active Enterprise ATT&CK technique and subtechnique IDs to
// their canonical names.
var Techniques = mitre.Techniques

// ValidTactic reports whether id is a known Enterprise ATT&CK tactic ID.
func ValidTactic(id string) bool { return mitre.ValidTactic(id) }

// ValidTechnique reports whether id is a known active Enterprise ATT&CK
// technique or subtechnique ID.
func ValidTechnique(id string) bool { return mitre.ValidTechnique(id) }

// TacticName returns the canonical name for the given tactic ID, or an empty
// string if the ID is not recognized.
func TacticName(id string) string { return mitre.TacticName(id) }

// TechniqueName returns the canonical name for the given technique or
// subtechnique ID, or an empty string if the ID is not recognized.
func TechniqueName(id string) string { return mitre.TechniqueName(id) }
