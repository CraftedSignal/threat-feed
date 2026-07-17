---
title: OpenClaw Authorization Flaw in QQBot Exec Approvals (CVE-2026-62217)
slug: 2026-07-openclaw-auth-flaw
description: An authorization flaw (CVE-2026-62217, CWE-863) in OpenClaw versions 2026.5.14-beta.1 before 2026.5.27 allows lower-trust callers or non-allowlisted senders to execute or persist unauthorized operations via the QQBot exec approvals feature, potentially leading to privilege escalation and system compromise.
date: "2026-07-17T02:27:19Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - authorization-bypass
  - cve
  - openclaw
  - qqbot
  - privilege-escalation
  - vulnerability
vendors:
  - OpenClaw
products:
  - OpenClaw
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: a lower-trust caller or configured input path could execute or persist actions beyond the caller's intended authorization, allowing non-allowlisted senders to perform unauthorized operations.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: could execute or persist actions beyond the caller's intended authorization
    confidence_band: med
cves:
  - id: CVE-2026-62217
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-62217
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-7jx6-764p-fgg9
  - https://www.vulncheck.com/advisories/openclaw-beta-1-authentication-bypass-via-exec-approvals
iocs:
  - type: url
    value: https://github.com/openclaw/openclaw/security/advisories/GHSA-7jx6-764p-fgg9
  - type: url
    value: https://www.vulncheck.com/advisories/openclaw-beta-1-authentication-bypass-via-exec-approvals
ioc_counts:
  url: 2
---

An authorization bypass vulnerability, identified as CVE-2026-62217, has been discovered in OpenClaw versions 2026.5.14-beta.1 prior to 2026.5.27. This flaw affects the QQBot exec approvals feature. When this feature is enabled and reachable, it fails to properly validate the authorization of callers or configured input paths. Consequently, a lower-trust entity or an un-allowlisted sender can perform actions that exceed their intended permissions, leading to unauthorized operations. This vulnerability bypasses core security controls, enabling potential privilege escalation, unauthorized data manipulation, or the establishment of persistence mechanisms within the affected OpenClaw environment. The vulnerability was published on July 17, 2026, and poses a significant risk to organizations using vulnerable OpenClaw installations.

## Attack Chain

1. **Vulnerable Component Identification**: An attacker identifies an OpenClaw instance running version 2026.5.14-beta.1 to 2026.5.26, where the QQBot exec approvals feature is enabled and network reachable.
2. **Request Crafting**: The attacker crafts a malicious request designed to interact with the QQBot exec approvals feature. This request originates from a lower-trust caller or a configured input path that would normally be restricted.
3. **Authorization Bypass**: Due to the authorization flaw (CWE-863), the OpenClaw application incorrectly processes the crafted request, failing to enforce proper permission checks for the sender.
4. **Unauthorized Execution Attempt**: The application interprets the request as if it originated from a fully authorized entity.
5. **Action Execution**: The application executes the actions specified in the attacker's request, which are beyond the legitimate scope of the original caller's authorization.
6. **Persistence or Privilege Escalation**: The attacker leverages the unauthorized execution to perform actions such as running arbitrary commands, modifying configurations, or establishing persistence mechanisms, effectively escalating privileges or maintaining unauthorized access.
7. **Impact on System**: The attacker successfully compromises the integrity and confidentiality of the OpenClaw environment by performing unauthorized operations, potentially leading to full system control.

## Impact

A successful exploitation of CVE-2026-62217 grants unauthorized entities the ability to execute or persist actions beyond their intended authorization. This means that non-allowlisted senders can perform malicious operations, leading to privilege escalation, data compromise, or the installation of persistent backdoors within the OpenClaw environment. While no specific victim numbers or targeted sectors are mentioned in the advisory, any organization utilizing vulnerable OpenClaw versions with the QQBot exec approvals feature enabled is at risk of significant security breaches, potentially impacting data integrity, confidentiality, and system availability.

## Recommendation

* **Patch CVE-2026-62217 immediately**: Upgrade OpenClaw installations to version 2026.5.27 or later to address the authorization flaw in the QQBot exec approvals feature.
* **Monitor QQBot Exec Approvals logs**: Implement enhanced logging and monitor system logs for OpenClaw's QQBot exec approvals feature for any unauthorized or unusual activity, specifically looking for executions originating from lower-trust callers or un-allowlisted senders.
