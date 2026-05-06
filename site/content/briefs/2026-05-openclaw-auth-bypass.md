---
title: OpenClaw Authentication Bypass in Feishu Webhook and Card Actions
slug: 2026-05-openclaw-auth-bypass
description: OpenClaw before version 2026.4.15 contains an authentication bypass vulnerability (CVE-2026-44109) in Feishu webhook and card-action validation, allowing unauthenticated requests to execute arbitrary commands due to insecure default configurations.
date: "2026-05-06T20:16:34Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - authentication bypass
  - webhook
  - card action
  - cve-2026-44109
vendors:
  - OpenClaw
products:
  - OpenClaw
  - Feishu webhook
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
cves:
  - id: CVE-2026-44109
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-44109
  - https://github.com/openclaw/openclaw/commit/c8003f1b33ed2924be5f62131bd28742c5a41aae
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-xh72-v6v9-mwhc
  - https://www.vulncheck.com/advisories/openclaw-authentication-bypass-in-feishu-webhook-and-card-action-validation
rules:
  - title: Detect OpenClaw Unauthenticated Webhook Request
    description: Detects requests to OpenClaw's Feishu webhook endpoints lacking proper authentication, indicating a potential CVE-2026-44109 exploitation attempt.
    platform: sigma
    severity: critical
    tactics:
      - credential_access
    techniques:
      - T1555
    data_sources:
      - webserver
      - linux
  - title: Detect OpenClaw Missing encryptKey Configuration
    description: Detects requests where callback_token is present but encryptKey is missing, indicative of a misconfigured OpenClaw instance vulnerable to CVE-2026-44109.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1555
    data_sources:
      - webserver
      - linux
rules_count: 2
---

OpenClaw before version 2026.4.15 is vulnerable to an authentication bypass in its Feishu webhook and card-action validation mechanisms. This vulnerability, identified as CVE-2026-44109, allows unauthenticated requests to reach command dispatch. The root cause lies in the application's handling of missing `encryptKey` configurations and blank callback tokens. Instead of rejecting requests lacking proper authentication, the system fails open, effectively bypassing signature verification and replay protection. This flaw enables attackers to execute arbitrary commands within the OpenClaw environment. This is a critical vulnerability due to the potential for unauthorized command execution leading to data manipulation, system compromise, or other malicious activities.

## Attack Chain

1. An attacker crafts a malicious request targeting the Feishu webhook or card-action endpoint within OpenClaw.
2. The attacker omits or provides a blank callback token and does not provide a valid `encryptKey`.
3. OpenClaw's authentication mechanism incorrectly validates the request due to the fail-open behavior when the `encryptKey` is missing or the callback token is blank.
4. The request bypasses signature verification and replay protection, normally intended to ensure request integrity and prevent tampering.
5. The unauthenticated request is passed to the command dispatch component.
6. The command dispatch component executes the attacker-supplied command without proper authorization checks.
7. The attacker achieves arbitrary command execution within the OpenClaw environment.
8. The attacker can then perform actions such as modifying data, accessing sensitive information, or compromising the OpenClaw system.

## Impact

Successful exploitation of CVE-2026-44109 allows unauthenticated attackers to execute arbitrary commands on OpenClaw systems. The impact is high, potentially leading to unauthorized access to sensitive data, modification of system configurations, or complete system compromise. Due to the nature of webhooks, this could potentially allow attackers to pivot to other systems integrated with OpenClaw, creating a significant security breach.

## Recommendation

*   Upgrade OpenClaw to version 2026.4.15 or later to patch CVE-2026-44109.
*   Ensure that a strong `encryptKey` is properly configured for Feishu webhook and card-action validation.
*   Deploy the Sigma rule `Detect OpenClaw Unauthenticated Webhook Request` to identify exploitation attempts (CVE-2026-44109).
*   Review and restrict access to Feishu webhook and card-action endpoints to only authorized sources.
