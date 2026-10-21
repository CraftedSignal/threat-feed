// Package publicfeed exposes the public brief contract used by the feed's
// deploy validation to other producers, including TI-Bot.
package publicfeed

import contract "github.com/craftedsignal/threat-feed/internal/publicfeed"

type Issue = contract.Issue

// CheckBrief validates the exact Markdown bytes before publication.
func CheckBrief(path string, markdown []byte) []Issue {
	return contract.CheckBrief(path, markdown)
}

// CheckBriefAppendOnly validates a revision against the currently public file.
func CheckBriefAppendOnly(path string, previous, current []byte) []Issue {
	return contract.CheckBriefAppendOnly(path, previous, current)
}
