---
title: Go Markdown Library Out-of-Bounds Read Vulnerability
slug: 2026-04-gomarkdown-oob-read
description: A vulnerability in the go-markdown library exists where processing a malformed input containing a '<' character that is not followed by a '>' character with a SmartypantsRenderer can lead to an out-of-bounds read or a panic, causing a denial of service.
date: "2026-04-15T12:00:00Z"
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

The `go-markdown` library, specifically versions prior to `0.0.0-20260411013819-759bbc3e3207`, is susceptible to an out-of-bounds read vulnerability. This flaw is triggered when the `SmartypantsRenderer` processes malformed markdown input containing a `<` character that is not subsequently closed by a `>` character within the remaining text. The vulnerability resides within the `smartLeftAngle()` function in `html/smartypants.go`. Exploitation of this vulnerability leads to either an…
