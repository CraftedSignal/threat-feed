---
title: Go-Markdown Library Vulnerable to Out-of-Bounds Read via Malformed Input
slug: 2026-04-gomarkdown-oob-read
description: The `github.com/gomarkdown/markdown` Go library is susceptible to an out-of-bounds read or panic when processing malformed input with the SmartypantsRenderer, potentially leading to a denial-of-service condition.
date: "2026-04-22T12:00:00Z"
type: coverage
types:
  - coverage
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
iocs:
  - type: url
    value: https://github.com/gomarkdown/markdown/commit/759bbc3e32073c3bc4e25969c132fc520eda2778
  - type: url
    value: https://github.com/gomarkdown/markdown/security/advisories/GHSA-77fj-vx54-gvh7
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

The `github.com/gomarkdown/markdown` library, a widely used Go package for parsing Markdown and rendering it as HTML, contains a vulnerability (CVE-2026-40890) that can be triggered by processing specially crafted Markdown input. Specifically, if the input contains a `<` character that is not subsequently closed by a `>` character, the SmartypantsRenderer will cause an out-of-bounds read or panic. This issue was introduced in an earlier version of the library and was addressed in commit 759bbc3e32073c3bc4e25969c132fc520eda2778. Exploitation of this vulnerability can lead to a denial-of-service (DoS) condition, affecting applications that rely on this library to process untrusted Markdown content. Defenders should ensure they are running a patched version of the library.

## Attack Chain

1.  An attacker crafts a malicious Markdown document containing a `<` character without a closing `>` character.
2.  A user or automated system submits the malicious Markdown document to an application using the vulnerable `github.com/gomarkdown/markdown` library.
3.  The application calls the `markdown.ToHTML` function with the crafted Markdown and uses `SmartypantsRenderer` to render to HTML.
4.  The `SmartypantsRenderer` attempts to process the malformed `<` character.
5.  Due to the missing `>`, the renderer attempts to read beyond the bounds of the input buffer, triggering an out-of-bounds read.
6.  The out-of-bounds read leads to a panic within the Go application.
7.  The panic crashes the Go application, causing a denial-of-service.

## Impact

Successful exploitation of this vulnerability results in a denial-of-service condition. Applications using the vulnerable version of `github.com/gomarkdown/markdown` may crash when processing attacker-controlled Markdown input. The severity of the impact depends on the role of the affected application; if it is a critical service, the denial of service could have significant consequences. The number of potential victims is proportional to the number of applications using the vulnerable `github.com/gomarkdown/markdown` library and processing potentially untrusted Markdown content.

## Recommendation

*   Update the `github.com/gomarkdown/markdown` library to a version containing commit 759bbc3e32073c3bc4e25969c132fc520eda2778 or later to remediate the vulnerability.
*   Implement input validation to sanitize Markdown input before processing it with the `github.com/gomarkdown/markdown` library.
