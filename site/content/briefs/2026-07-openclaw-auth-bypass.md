---
title: OpenClaw Authorization Bypass Vulnerability (CVE-2026-62195)
slug: 2026-07-openclaw-auth-bypass
description: An authorization bypass vulnerability, CVE-2026-62195, in OpenClaw versions 2026.5.20 before 2026.6.6 allows lower-trust callers to execute owner-only tools via the MCP loopback feature, potentially leading to privilege escalation, unauthorized execution, and persistence with high impact on confidentiality and integrity.
date: "2026-07-13T22:27:37Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - authorization-bypass
  - privilege-escalation
  - openclaw
vendors:
  - OpenClaw
products:
  - OpenClaw (2026.5.20 before 2026.6.6)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: allows lower-trust callers to execute owner-only tools. Attackers can bypass authorization checks through configured input paths to execute or persist actions beyond their intended permissions.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: allows lower-trust callers to execute owner-only tools.
    confidence_band: med
cves:
  - id: CVE-2026-62195
    cvss: 8.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-62195
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-52xj-c9p8-78cv
  - https://www.vulncheck.com/advisories/openclaw-authorization-bypass-via-mcp-loopback
---

A critical authorization bypass vulnerability, identified as CVE-2026-62195, has been discovered in OpenClaw versions 2026.5.20 through 2026.6.5. This flaw resides within the MCP loopback feature, enabling attackers with lower trust levels to execute tools intended only for owners. By manipulating configured input paths, unauthorized individuals can bypass existing authorization checks, allowing them to execute or persist actions with elevated privileges. This vulnerability can lead to unauthorized access, privilege escalation, and potentially full system compromise. The CVSS 3.1 base score for this vulnerability is 8.3, indicating a high severity risk with significant impact on confidentiality and integrity. Defenders should prioritize patching affected OpenClaw instances to prevent attackers from exploiting this vulnerability to gain unauthorized control and establish persistence.

## Attack Chain

This vulnerability describes an authorization bypass rather than a multi-stage attack chain with distinct steps for initial access. The exploitation occurs at a specific point within the application's logic.

1. A lower-trust caller interacts with the OpenClaw application, specifically targeting the MCP loopback feature.
2. The attacker crafts input through a configured input path, designed to bypass authorization checks.
3. The vulnerability in OpenClaw (versions 2026.5.20 before 2026.6.6) fails to properly enforce access controls for the MCP loopback.
4. The crafted input allows the lower-trust caller to execute owner-only tools, effectively escalating privileges.
5. Through the execution of owner-only tools, the attacker can then perform unauthorized actions or establish persistence beyond their legitimate permissions.

## Impact

Successful exploitation of CVE-2026-62195 can result in severe consequences for affected organizations. Attackers can gain unauthorized control over the OpenClaw system by executing privileged "owner-only tools." This directly leads to privilege escalation, allowing attackers to access sensitive data, modify system configurations, or install persistent backdoors. The vulnerability has a high impact on confidentiality and integrity, meaning critical information could be exfiltrated or tampered with. It also presents a moderate impact on availability, as unauthorized actions could lead to service disruption. While specific victim counts or targeted sectors are not available, any organization utilizing vulnerable OpenClaw versions is at risk of unauthorized access and potential system compromise.

## Recommendation

* Patch CVE-2026-62195 by upgrading OpenClaw to version 2026.6.6 or later immediately, as specified in the NVD and GitHub advisories.
* Monitor OpenClaw system logs for unusual or unauthorized execution of "owner-only tools" by lower-trust accounts, correlating with activity around the MCP loopback feature.
