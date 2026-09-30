---
title: Quadratic Time Denial of Service in league/commonmark Table Extension
slug: 2026-09-league-commonmark-dos
description: An unauthenticated remote attacker can cause denial of service by submitting large Markdown paragraphs that trigger O(M^2) CPU consumption in the league/commonmark TableStartParser.
date: "2026-09-30T16:27:25Z"
type: advisory
types:
  - advisory
severities:
  - medium
vendors:
  - thephpleague
products:
  - commonmark (>= 2.0.0, <= 2.10.1)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: An unauthenticated user who submits a single large paragraph of pipe-free lines that do not begin with a letter drives seconds to tens of seconds of single-core CPU that grows quadratically with body size, enough to exhaust worker processes and deny service.
    confidence_band: high
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - Application Security
  immediate_actions:
    - action: Audit applications using league/commonmark and implement input length limits as an interim mitigation.
      owner: Application Security
      due: 24h
      evidence: Source suggests capping the size of untrusted Markdown as a mitigation.
  mitigation_plan:
    - priority: immediate
      action: Disable the Table extension for untrusted input processing until a patch is applied.
      owner: Application Security
      addresses: O(M^2) complexity path in TableStartParser
      evidence: Source advises disabling the extension to reduce exposure.
---

The `league/commonmark` library, specifically in versions 2.0.0 through 2.10.1, contains a quadratic-time complexity vulnerability in its GitHub Flavored Markdown (GFM) Table extension. The `TableStartParser` performs a full-buffer scan of the accumulated paragraph on every new line via `strpos()` to check for potential table headers. Because the paragraph buffer grows indefinitely as long as non-blank lines are provided, and the scan traverses this entire buffer repeatedly, the work required grows quadratically (O(M^2)) relative to the input size. An unauthenticated attacker can exploit this by submitting large paragraphs consisting of lines that do not start with a letter (bypassing the `SkipLinesStartingWithLettersParser`) and contain no pipe characters. This causes excessive CPU usage, which can exhaust available PHP worker processes and result in a denial of service.

## Attack Chain

1. **Exposure:** The attacker identifies an application using `league/commonmark` (specifically with `GithubFlavoredMarkdownConverter` or the `TableExtension` enabled) that processes untrusted Markdown content.
2. **Control:** The attacker prepares a large Markdown body consisting of a single paragraph with no blank lines, no pipe (`|`) characters, and lines beginning with non-letter characters (e.g., digits).
3. **Path:** As the parser processes the input, the `ParagraphParser` keeps the paragraph block open, causing the library to append each line to the growing `paragraph` buffer.
4. **Bypass:** Since the input lines do not begin with a letter, the `SkipLinesStartingWithLettersParser` returns `BlockStart::abort()`, allowing the parser to continue searching for other block types.
5. **Primitive:** The `MarkdownParser` dispatches the input to the `TableStartParser::tryStart()` on every line, which executes `strpos($paragraph, '|')` against the entire, continuously growing buffer.
6. **Guard Absence:** No input-size caps or effective length guards prevent the cumulative buffer growth or the exhaustive scan, allowing the O(M^2) complexity to manifest.
7. **Result:** The cumulative processing time leads to extreme CPU load, effectively exhausting server resources and denying service to legitimate users.

## Impact

Successful exploitation results in a denial of service by consuming all available server resources or PHP worker threads. The impact is limited to availability, with no risk to data confidentiality or integrity. Applications rendering untrusted Markdown from external users are at the highest risk. Measured benchmarks demonstrate that doubling a multi-megabyte input quadruples the CPU time, with 200,000 lines taking approximately 27.81 seconds to parse.

## Recommendation

1. Upgrade `league/commonmark` to a version where this vulnerability is remediated (as of this writing, no fix is available; monitor the upstream repository for updates).
2. Implement application-level constraints on the total length of user-submitted Markdown content before passing it to the converter.
3. If not required, disable the `TableExtension` in the `GithubFlavoredMarkdownConverter` configuration when processing untrusted input.
4. Monitor application server CPU usage patterns specifically for PHP-FPM worker saturation coinciding with requests to Markdown rendering endpoints.
