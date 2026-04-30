---
title: SciTokens Library Path Traversal Vulnerability (CVE-2026-32727)
slug: 2024-01-23-scitokens-path-traversal
description: A path traversal vulnerability (CVE-2026-32727) in SciTokens library versions prior to 1.9.7 allows attackers to bypass intended directory restrictions using dot-dot sequences in the scope claim of a token due to improper path normalization.
date: "2026-03-31T03:15:57Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - scitokens
  - path-traversal
  - cve-2026-32727
  - vulnerability
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-32727
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-32727
rules:
  - title: Detect SciTokens Path Traversal Attempt via HTTP Request
    description: Detects potential path traversal attempts in HTTP requests targeting SciTokens-protected resources by looking for '..' sequences in the URI query or path.
    platform: sigma
    severity: high
    tactics:
      - resource_development
    techniques:
      - T1588.006
    data_sources:
      - webserver
      - linux
  - title: Detect SciTokens Path Traversal Attempt in Web Logs
    description: Detects path traversal attempts using '..' sequences within web server logs, indicating a potential SciTokens scope bypass.
    platform: sigma
    severity: high
    tactics:
      - resource_development
    techniques:
      - T1588.006
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The SciTokens library, a reference implementation for generating and using SciTokens, is susceptible to a path traversal vulnerability affecting versions prior to 1.9.7. This vulnerability, identified as CVE-2026-32727, stems from the library's Enforcer component. An attacker can exploit this flaw by crafting a malicious token containing a scope claim with "dot-dot" (..) sequences. These sequences allow the attacker to navigate outside the intended directory restriction, potentially accessing…
