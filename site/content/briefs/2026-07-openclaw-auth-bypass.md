---
title: OpenClaw Authorization Bypass Vulnerability via Exec Allowlist Glob Matching (CVE-2026-62229)
slug: 2026-07-openclaw-auth-bypass
description: OpenClaw versions prior to 2026.5.18 contain an authorization bypass vulnerability (CVE-2026-62229) in its exec allowlist glob matching feature, allowing lower-trust callers to execute or persist unauthorized actions by crafting input paths that traverse the allowlist patterns, potentially leading to system compromise.
date: "2026-07-17T02:34:09Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - authorization-bypass
  - path-traversal
  - privilege-escalation
  - openclaw
vendors:
  - OpenClaw
products:
  - OpenClaw < 2026.5.18
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: allows lower-trust callers to execute actions beyond intended authorization
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: execute actions beyond intended authorization
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: persist unauthorized actions when the affected feature is enabled
    confidence_band: med
cves:
  - id: CVE-2026-62229
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-62229
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-34mr-7r3m-gfg7
  - https://www.vulncheck.com/advisories/openclaw-authorization-bypass-via-glob-matching
iocs:
  - type: url
    value: https://github.com/openclaw/openclaw/security/advisories/GHSA-34mr-7r3m-gfg7
  - type: url
    value: https://www.vulncheck.com/advisories/openclaw-authorization-bypass-via-glob-matching
ioc_counts:
  url: 2
---

A critical authorization bypass vulnerability, identified as CVE-2026-62229, affects OpenClaw software versions released before 2026.5.18. This flaw resides specifically within the `exec` allowlist glob matching functionality, which is designed to restrict actions based on trust levels. However, a malicious actor or lower-trust caller can exploit this vulnerability by carefully constructing input paths that leverage directory traversal sequences. By doing so, they can bypass the intended authorization controls and execute or persist actions that fall outside their assigned permissions, even when the `exec` allowlist feature is enabled. The vulnerability could lead to arbitrary code execution, unauthorized data manipulation, or system compromise depending on the context of the unauthorized actions performed. This vulnerability was published on July 17, 2026, and carries a CVSS v3.1 Base Score of 8.8, indicating a high severity risk.

## Attack Chain

1. A lower-trust caller (e.g., an authenticated user with limited privileges) gains access to the OpenClaw application.
2. The attacker identifies an input mechanism within OpenClaw that utilizes the `exec` allowlist glob matching feature for path validation.
3. The attacker crafts a malicious input string that combines directory traversal sequences (e.g., `../../`) with valid glob patterns expected by the application.
4. This crafted input path is submitted to the vulnerable OpenClaw feature, exploiting the authorization bypass.
5. Due to the vulnerability (CVE-2026-62229), the application incorrectly processes the input, allowing the crafted path to bypass intended restrictions.
6. OpenClaw then executes or persists an unauthorized action on the underlying system, such as running arbitrary commands, modifying sensitive files, or establishing persistence mechanisms, despite the user's lower trust level.

## Impact

Successful exploitation of CVE-2026-62229 allows lower-trust callers to execute or persist unauthorized actions, effectively escalating their privileges within the OpenClaw environment and potentially impacting the underlying operating system. The consequences can range from unauthorized data modification and sensitive information disclosure to full system compromise, depending on the capabilities granted by the bypass and the attacker's objectives. Organizations using affected OpenClaw versions are at risk of suffering unauthorized access, data integrity loss, and potential business disruption if this vulnerability is exploited.

## Recommendation

* Patch CVE-2026-62229 immediately by upgrading OpenClaw to version 2026.5.18 or later, as referenced in the provided GitHub advisory URL and VulnCheck advisory URL.
