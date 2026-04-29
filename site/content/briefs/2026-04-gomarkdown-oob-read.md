---
title: Go Markdown Library Out-of-Bounds Read Vulnerability
slug: 2026-04-gomarkdown-oob-read
description: A vulnerability in the go-markdown library exists where processing a malformed input containing a '<' character that is not followed by a '>' character with a SmartypantsRenderer can lead to an out-of-bounds read or a panic, causing a denial of service.
date: "2026-04-15T12:00:00Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - markdown
  - denial-of-service
  - go
  - out-of-bounds read
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://github.com/advisories/GHSA-77fj-vx54-gvh7
  - https://github.com/gomarkdown/markdown/blob/37c66b85d6ab025ba67a73ba03b7f3ef55859cca/html/smartypants.go#L367-L376
rules:
  - title: Detect Go Markdown Smartypants Panic
    description: Detects panics originating from the `go-markdown` library related to the SmartypantsRenderer, indicating a potential out-of-bounds read vulnerability.
    platform: sigma
    severity: high
    tactics:
      - availability
    techniques:
      - T1499.002
    data_sources:
      - application
      - linux
  - title: Detect Suspicious Input to Markdown Processor
    description: Detects HTTP requests that include suspicious unclosed HTML-like tags being sent to a markdown processing service.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The `go-markdown` library, specifically versions prior to `0.0.0-20260411013819-759bbc3e3207`, is susceptible to an out-of-bounds read vulnerability. This flaw is triggered when the `SmartypantsRenderer` processes malformed markdown input containing a `<` character that is not subsequently closed by a `>` character within the remaining text. The vulnerability resides within the `smartLeftAngle()` function in `html/smartypants.go`. Exploitation of this vulnerability leads to either an out-of-bounds read (if the slice length is less than its capacity) or a panic (if the slice length equals its capacity), ultimately resulting in a denial of service. This issue affects applications utilizing the vulnerable versions of the `go-markdown` library for markdown processing.

## Attack Chain

1. An attacker crafts a malicious markdown input string containing an unclosed `<` tag (e.g., `<a`).
2. The application receives the crafted markdown input for processing.
3. The application uses the `go-markdown` library with the `SmartypantsRenderer` enabled to render the markdown input.
4. The `SmartypantsRenderer` calls the `smartLeftAngle()` function in `html/smartypants.go` to handle the `<` character.
5. The `smartLeftAngle()` function encounters the unclosed `<` tag, triggering the out-of-bounds read due to missing `>` character.
6. Depending on the slice's length and capacity, the program either reads an extra byte of data (if length < capacity) or panics (if length == capacity).
7. The application crashes due to the panic or becomes unstable due to the out-of-bounds read.
8. Service availability is disrupted, resulting in a denial-of-service condition.

## Impact

Successful exploitation of this vulnerability leads to a denial of service. Any service using the vulnerable `go-markdown` library to process potentially malicious markdown input is susceptible to crashing or becoming unstable. The impact is a loss of availability for the affected service. While the specific number of affected services or sectors is not mentioned in the source, any application relying on `go-markdown` is potentially vulnerable.

## Recommendation

*   Upgrade the `go-markdown` library to version `0.0.0-20260411013819-759bbc3e3207` or later to patch the vulnerability as detailed in the overview.
*   Implement input validation to sanitize or reject markdown input containing unclosed `<` tags. This mitigates the risk even if the vulnerable library is used.
*   Monitor application logs for unexpected panics or errors originating from the `go-markdown` library, specifically around markdown rendering routines.
