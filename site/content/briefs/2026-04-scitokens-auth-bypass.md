---
title: SciTokens Authorization Bypass Vulnerability (CVE-2026-32716)
slug: 2026-04-scitokens-auth-bypass
description: SciTokens versions prior to 1.9.6 incorrectly validate scope paths using a prefix match, leading to an authorization bypass vulnerability where a token with access to a specific path can access sibling paths with the same prefix.
date: "2026-03-31T03:17:16Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - authorization-bypass
  - scitokens
  - CVE-2026-32716
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-32716
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-32716
  - https://github.com/scitokens/scitokens/commit/7a237c0f642efb9e8c36ac564b745895cca83583
  - https://github.com/scitokens/scitokens/releases/tag/v1.9.6
  - https://github.com/scitokens/scitokens/security/advisories/GHSA-w8fp-g9rh-34jh
rules:
  - title: SciTokens Authorization Bypass Attempt (Path Prefix)
    description: Detects attempts to access resources with path prefixes, potentially indicating exploitation of CVE-2026-32716.
    platform: sigma
    severity: medium
    tactics:
      - cve-2026-32716
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: SciTokens Version Detection via User-Agent
    description: Detects clients potentially using vulnerable SciTokens library versions based on User-Agent strings.
    platform: sigma
    severity: informational
    tactics:
      - discovery
    data_sources:
      - webserver
      - linux
rules_count: 2
---

SciTokens is a reference library for generating and using SciTokens. Versions prior to 1.9.6 are vulnerable to an authorization bypass. The vulnerability, identified as CVE-2026-32716, stems from incorrect validation of scope paths within the Enforcer component. Instead of performing an exact match, the Enforcer uses a simple prefix match (startswith). This flaw allows a token authorized for a specific path (e.g., `/john`) to also gain unauthorized access to sibling paths sharing the same…
