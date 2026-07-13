---
title: OpenClaw Authorization Bypass Vulnerability in OpenAI-compatible Overrides (CVE-2026-62186)
slug: 2026-07-openclaw-auth-bypass
description: An authorization bypass vulnerability, CVE-2026-62186, exists in OpenClaw versions prior to 2026.6.8, affecting its OpenAI-compatible HTTP model overrides, allowing lower-trust callers to perform actions requiring stronger authorization checks and potentially leading to privilege escalation by bypassing admin authorization policies via misconfigured input paths.
date: "2026-07-13T22:23:05Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - authorization-bypass
  - vulnerability
  - web-application
  - privilege-escalation
vendors:
  - OpenClaw
products:
  - OpenClaw versions < 2026.6.8
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Attackers can exploit misconfigured input paths to bypass admin authorization policies and execute restricted operations.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: allows lower-trust callers to perform actions requiring stronger authorization checks. Attackers can exploit misconfigured input paths to bypass admin authorization policies and execute restricted operations.
    confidence_band: high
cves:
  - id: CVE-2026-62186
    cvss: 7.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-62186
---

A critical authorization bypass vulnerability, identified as CVE-2026-62186, affects OpenClaw versions before 2026.6.8. This flaw specifically impacts the OpenAI-compatible HTTP model overrides feature within the application. The vulnerability allows users or processes with lower trust levels to execute operations that typically require elevated permissions or administrative authorization. Attackers can exploit this by manipulating misconfigured input paths, effectively circumventing the established security policies. Successful exploitation could lead to privilege escalation, allowing unauthorized execution of restricted functions or access to sensitive data and controls. The vulnerability has a CVSS v3.1 Base Score of 7.6, indicating a high severity risk.

## Attack Chain

1. An unauthenticated or low-privileged attacker identifies a vulnerable OpenClaw instance running a version prior to 2026.6.8.
2. The attacker crafts a malicious HTTP request targeting the OpenAI-compatible HTTP model overrides feature.
3. The request exploits a misconfigured input path within the application's handling of these overrides.
4. Due to the authorization bypass, the application fails to enforce proper administrative or higher-level authorization checks.
5. The attacker successfully executes an action or operation that would normally require stronger permissions.
6. This leads to privilege escalation, enabling the attacker to perform restricted operations within the OpenClaw environment.

## Impact

Successful exploitation of CVE-2026-62186 allows an attacker to bypass critical authorization mechanisms within OpenClaw. This can lead to privilege escalation, granting unauthorized access to administrative functions or other restricted operations. The immediate consequences include unauthorized data manipulation, access to sensitive information, or disruption of services. Organizations using affected OpenClaw versions could face significant security breaches, data integrity issues, and compliance violations if this vulnerability is exploited in production environments.

## Recommendation

* Immediately update all OpenClaw instances to version 2026.6.8 or later to patch CVE-2026-62186.
* Review access control configurations and logging for OpenClaw's OpenAI-compatible HTTP model overrides to identify any unusual activity.
