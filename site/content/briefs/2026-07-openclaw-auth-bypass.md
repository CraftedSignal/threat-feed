---
title: Authentication Bypass Vulnerability in OpenClaw (CVE-2026-62207)
slug: 2026-07-openclaw-auth-bypass
description: OpenClaw versions before 2026.6.5 are affected by an authentication bypass vulnerability (CVE-2026-62207) that allows lower-trust callers to access and utilize administrative tools, effectively escalating their privileges by exploiting insufficient policy checks on configured input paths, enabling attackers to perform actions requiring stronger authorization.
date: "2026-07-17T02:24:37Z"
lastmod: "2026-07-17T02:25:41Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - authentication-bypass
  - vulnerability
  - web
  - cve
  - authorization-bypass
  - openclaw
vendors:
  - OpenClaw
products:
  - OpenClaw (< 2026.6.5)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Attackers can perform actions requiring stronger authorization by exploiting insufficient policy checks on configured input paths.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: OpenClaw versions 2026.5.10-beta.1 before 2026.6.5 contain an authorization bypass in the ClickClack agent-mode dispatch feature, which could ignore the toolsAllow policy check. When the affected feature is enabled and reachable, a lower-trust caller or configured input path could perform actions that should have required a stronger authorization or policy check.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: a lower-trust caller or configured input path could perform actions that should have required a stronger authorization or policy check.
    confidence_band: high
cves:
  - id: CVE-2026-62207
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-62207
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-cf2p-f286-mphf
  - https://nvd.nist.gov/vuln/detail/CVE-2026-62209
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-wp73-f3gg-w4vr
  - https://www.vulncheck.com/advisories/openclaw-beta-1-authorization-bypass-via-agent-mode-dispatch
updates:
  - at: "2026-07-17T02:25:41Z"
    level: L2
    summary: 'merged source coverage: OpenClaw Authorization Bypass Vulnerability CVE-2026-62209'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-62209
---

OpenClaw versions prior to 2026.6.5 are susceptible to an authentication bypass vulnerability, tracked as CVE-2026-62207. This flaw stems from insufficient policy checks (CWE-862) on configured input paths within the application, allowing users with lower trust levels to access and utilize administrative functionalities. An attacker who has authenticated with standard user privileges can leverage this vulnerability to bypass authorization checks, gain access to tools intended for administrators, and execute actions that normally require higher authorization. This significantly elevates the attacker's capabilities within the affected system, potentially leading to unauthorized data manipulation, configuration changes, or full system compromise. The vulnerability was published on July 16, 2026, and affects all instances running versions older than 2026.6.5.

## Attack Chain

1. An attacker gains initial access to an OpenClaw application instance with lower-trust credentials, typically through a standard user account.
2. The attacker identifies or crafts a request targeting admin-scoped tools or functionalities within the OpenClaw application.
3. The attacker manipulates the configured input paths in the request, attempting to bypass standard authorization checks.
4. Due to the insufficient policy checks (CWE-862) implemented in affected OpenClaw versions, the application fails to properly validate the attacker's authorization for the requested admin-scoped action.
5. The application grants access to the administrative tool or functionality, treating the lower-trust caller's request as if it originated from a fully authorized administrator.
6. The attacker successfully executes actions typically restricted to administrators, such as configuration changes, user management, or data modification, leveraging the escalated privileges.

## Impact

A successful exploitation of CVE-2026-62207 allows attackers to bypass intended authorization boundaries within the OpenClaw application. This can lead to a severe compromise of the application's integrity, confidentiality, and availability. Attackers can gain unauthorized control over critical system functions, potentially altering configurations, exfiltrating sensitive data, or disrupting services. The impact can extend to any data managed by the OpenClaw instance and any connected systems if the administrative tools provide further access. While specific victim counts are not available, any organization running vulnerable OpenClaw instances faces a high risk of privilege escalation and subsequent malicious activity.

## Recommendation

* Immediately patch CVE-2026-62207 by updating all OpenClaw instances to version 2026.6.5 or later, as recommended in the GitHub advisory `https://github.com/openclaw/openclaw/security/advisories/GHSA-cf2p-f286-mphf`.
* Monitor web server logs for suspicious access patterns to administrative paths (`cs-uri-stem`) originating from user accounts with typically lower privilege levels.
* Deploy a Web Application Firewall (WAF) to filter and inspect requests, specifically focusing on parameters or input paths (`cs-uri-query`, `cs-uri-stem`) that could be manipulated to bypass authorization for administrative functions.
