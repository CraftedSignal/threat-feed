---
title: OpenClaw Authorization Bypass via WhatsApp Group IDs (CVE-2026-62196)
slug: 2026-07-openclaw-auth-bypass
description: An authorization bypass vulnerability, CVE-2026-62196, in OpenClaw versions 2026.3.22 before 2026.6.6 allows attackers with lower-trust access to perform actions requiring stronger authorization by leveraging WhatsApp group ID validation.
date: "2026-07-13T22:28:18Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - authorization-bypass
  - privilege-escalation
  - web-application
  - cve
vendors:
  - OpenClaw
products:
  - OpenClaw (2026.3.22 before 2026.6.6)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Attackers with lower-trust access can perform actions requiring stronger authorization by leveraging group ID validation in the affected feature.
    confidence_band: high
cves:
  - id: CVE-2026-62196
    cvss: 8.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-62196
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-fh38-965w-f6c3
  - https://www.vulncheck.com/advisories/openclaw-authorization-bypass-via-whatsapp-group-ids
---

OpenClaw versions 2026.3.22 up to, but not including, 2026.6.6 are affected by an authorization bypass vulnerability, identified as CVE-2026-62196. This flaw stems from an improper validation mechanism where WhatsApp group IDs can be misused to satisfy elevated sender allowlists. Attackers who possess lower-trust access can exploit this vulnerability to circumvent the intended authorization checks, thereby gaining the ability to execute operations that typically demand higher levels of privilege within the OpenClaw system. This vulnerability allows for unauthorized access to sensitive functionalities and data manipulation. The CVSS v3.1 Base Score for this vulnerability is 8.3, classifying it as a high-severity issue that could lead to significant unauthorized control or data compromise.

## Attack Chain

1. An attacker obtains initial, lower-trust access to an OpenClaw instance.
2. The attacker identifies a feature within OpenClaw that performs authorization checks based on WhatsApp group ID validation.
3. The attacker crafts a malicious request or input that includes a WhatsApp group ID designed to satisfy the elevated sender allowlist criteria.
4. This specially crafted request is sent to the vulnerable OpenClaw application, bypassing the intended authorization controls.
5. OpenClaw processes the request, mistakenly granting the attacker privileges or access beyond their assigned trust level.
6. The attacker then performs unauthorized actions, such as accessing sensitive data, modifying configurations, or executing commands that would otherwise require higher authorization.

## Impact

The successful exploitation of CVE-2026-62196 can lead to significant unauthorized access and privilege escalation within affected OpenClaw deployments. Attackers can bypass critical security mechanisms, potentially gaining control over sensitive application features or data. This could result in unauthorized data disclosure, data manipulation, or disruption of service, depending on the specific functionalities accessible with elevated privileges. While no specific victim counts or targeted sectors are detailed, any organization utilizing vulnerable OpenClaw versions is at risk of severe compromise if exposed.

## Recommendation

* Patch CVE-2026-62196 immediately by upgrading OpenClaw to version 2026.6.6 or later as recommended in the references.
* Review access logs for unusual activity originating from lower-trust accounts or unexpected source IP addresses, focusing on any attempts to interact with features that process WhatsApp group IDs or require elevated privileges.
