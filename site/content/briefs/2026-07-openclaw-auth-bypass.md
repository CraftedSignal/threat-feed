---
title: OpenClaw Authorization Bypass Vulnerability
slug: 2026-07-openclaw-auth-bypass
description: A vulnerability, identified as CVE-2026-62219, in OpenClaw versions 2026.2.12 before 2026.5.26 allows a lower-trust caller to bypass agent ID restrictions by submitting blank agent IDs during the `hooks.allowedAgentIds` validation, leading to unauthorized actions and effective privilege escalation.
date: "2026-07-17T02:29:14Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - authorization-bypass
  - vulnerability
  - cve
  - privilege-escalation
vendors:
  - OpenClaw
products:
  - OpenClaw (before 2026.5.26)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: A lower-trust caller or configured input path can bypass agent ID restrictions by submitting blank agent IDs, allowing actions that should require stronger authorization or policy checks.
    confidence_band: high
cves:
  - id: CVE-2026-62219
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-62219
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-724r-v4wf-mqc5
  - https://www.vulncheck.com/advisories/openclaw-authorization-bypass-via-blank-agent-ids
---

A critical authorization bypass vulnerability, tracked as CVE-2026-62219, has been discovered in OpenClaw versions 2026.2.12 through 2026.5.25. This flaw resides within the `hooks.allowedAgentIds` validation mechanism. A malicious actor, operating with lower trust or through a configured input path, can circumvent existing agent ID restrictions by supplying blank agent IDs. This bypass enables the actor to execute actions that should ordinarily demand a higher level of authorization or adhere to stricter policy controls. This vulnerability directly impacts the security integrity of OpenClaw deployments and could lead to unauthorized access to sensitive functions or data.

## Attack Chain

1. **Vulnerable Component Identification**: An attacker identifies an OpenClaw instance running an affected version (2026.2.12 before 2026.5.26) that relies on the `hooks.allowedAgentIds` validation for authorization.
2. **Access as Lower-Trust User**: The attacker gains initial access or already possesses credentials as a user with lower authorization within the OpenClaw application.
3. **Request Crafting with Blank Agent ID**: The attacker crafts a specific request or input, targeting functionality protected by `allowedAgentIds` validation, and intentionally includes blank agent IDs in the request.
4. **Authorization Bypass**: The vulnerable OpenClaw application's `hooks.allowedAgentIds` validation component fails to correctly process or reject these blank agent IDs, thus bypassing the intended agent ID restrictions.
5. **Unauthorized Action Execution**: The application proceeds to execute the requested action, treating the blank agent ID as valid or unrestricted, thereby circumventing established security policies and authorization checks.
6. **Privilege Escalation/Access**: The attacker successfully performs actions or accesses resources that should have been strictly limited to higher-privileged users or specific, validated agent IDs, resulting in an effective privilege escalation.

## Impact

The successful exploitation of CVE-2026-62219 allows an attacker to perform unauthorized actions within the OpenClaw application that should typically be restricted to users with stronger authorization. This can lead to privilege escalation, enabling the attacker to gain access to sensitive data, modify critical configurations, or execute administrative functions without proper permission. The exact scope of impact depends on the specific functionalities protected by the `allowedAgentIds` validation, but any such functionality could be compromised. Organizations using vulnerable OpenClaw versions face a significant risk of data breaches, system integrity compromise, and unauthorized operational control.

## Recommendation

* Patch CVE-2026-62219 by upgrading OpenClaw to version 2026.5.26 or later immediately.
* Review application logs for any instances of requests containing blank agent IDs, especially for actions requiring elevated privileges, as this could indicate attempted or successful exploitation of CVE-2026-62219.
