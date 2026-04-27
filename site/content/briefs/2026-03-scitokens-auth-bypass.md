---
title: SciTokens C++ Authorization Bypass Vulnerability (CVE-2026-32725)
slug: 2026-03-scitokens-auth-bypass
description: SciTokens C++ library before 1.4.1 is vulnerable to an authorization bypass (CVE-2026-32725) due to improper path normalization, allowing attackers to escalate privileges by using parent-directory traversal in scope claims.
date: "2026-03-31T18:16:50Z"
severities:
  - high
tags:
  - authorization-bypass
  - privilege-escalation
  - cve
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-32725
    cvss: 8.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-32725
rules:
  - title: Detect Suspicious SciTokens Scope
    description: Detects potentially malicious SciTokens scope with parent directory traversal attempts ('..')
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect SciTokens C++ Error Logs Indicating Exploitation
    description: Detects error logs from SciTokens C++ library related to scope processing failures that might indicate exploitation attempts related to CVE-2026-32725.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The SciTokens C++ library, a minimal library for creating and using SciTokens, contains an authorization bypass vulnerability (CVE-2026-32725) in versions prior to 1.4.1. This flaw stems from the library's handling of path-based scopes within tokens. Specifically, the library normalizes the scope path from the token before authorization but improperly collapses ".." path components instead of rejecting them. This can lead to a significant security risk, allowing attackers to manipulate scope…
