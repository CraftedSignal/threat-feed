---
title: Go-Markdown Library Vulnerable to Out-of-Bounds Read via Malformed Input
slug: 2026-04-gomarkdown-oob-read
description: The `github.com/gomarkdown/markdown` Go library is susceptible to an out-of-bounds read or panic when processing malformed input with the SmartypantsRenderer, potentially leading to a denial-of-service condition.
date: "2026-04-22T12:00:00Z"
severities:
  - medium
tags:
  - markdown
  - go
  - denial-of-service
  - cve-2026-40890
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
cves:
  - id: CVE-2026-40890
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40890
  - https://github.com/gomarkdown/markdown/commit/759bbc3e32073c3bc4e25969c132fc520eda2778
  - https://github.com/gomarkdown/markdown/security/advisories/GHSA-77fj-vx54-gvh7
ioc_counts:
  url: 2
rules:
  - title: Detect Go process with gomarkdown library and suspicious arguments
    description: Detects Go processes that import the 'github.com/gomarkdown/markdown' library and process suspicious input, potentially indicating exploitation of CVE-2026-40890.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1499.004
    data_sources:
      - process_creation
      - linux
  - title: Detect network connection to github commit URL
    description: Detects network connections to the GitHub commit URL associated with the fix for CVE-2026-40890, potentially indicating attempts to retrieve the patch or exploit details.
    platform: sigma
    severity: low
    tactics:
      - reconnaissance
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

The `github.com/gomarkdown/markdown` library, a widely used Go package for parsing Markdown and rendering it as HTML, contains a vulnerability (CVE-2026-40890) that can be triggered by processing specially crafted Markdown input. Specifically, if the input contains a `<` character that is not subsequently closed by a `>` character, the SmartypantsRenderer will cause an out-of-bounds read or panic. This issue was introduced in an earlier version of the library and was addressed in commit…
