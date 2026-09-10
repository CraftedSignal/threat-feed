---
title: CyberPanel Authentication Bypass via API
slug: 2026-09-cyberpanel-auth-bypass
description: CyberPanel versions prior to 3.0.5 contain an authentication bypass vulnerability where two-factor authentication is not enforced on API endpoints, allowing credential-derived token misuse.
date: "2026-09-10T15:16:32Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:cyberpanel:cyberpanel:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - authentication-bypass
  - cve-2026-88895
vendors:
  - CyberPanel
products:
  - CyberPanel (< 3.0.5)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
    evidence: Attackers who obtain an administrator's password can derive API tokens and perform administrative operations or create authenticated sessions without the second factor.
    confidence_band: high
cves:
  - id: CVE-2026-88895
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-88895
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade CyberPanel to 3.0.5 or later
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-88895 mitigation guidance
  mitigation_plan:
    - priority: immediate
      action: Upgrade to version 3.0.5
      owner: IT Operations
      addresses: CVE-2026-88895
      evidence: Source advisory
---

CyberPanel versions prior to 3.0.5 are vulnerable to an authentication bypass due to the failure to enforce two-factor authentication (TOTP) on API endpoints. An attacker who obtains an administrator's password can derive API tokens, effectively bypassing the second-factor requirement to execute administrative operations or establish unauthorized sessions. This vulnerability impacts the control plane of the CyberPanel environment, potentially allowing attackers to gain full administrative access to hosted web services and panel configurations. Defenders should prioritize patching to version 3.0.5 or later to restore TOTP integrity for all API-based authentication attempts.

## Impact

Successful exploitation allows an attacker to bypass MFA protections and gain administrative access to CyberPanel. This leads to full administrative control over the panel, enabling configuration changes, service disruption, and access to all managed web content and databases.

## Recommendation

1. Patch all CyberPanel instances to version 3.0.5 or later immediately to enforce TOTP on API endpoints.
2. Implement monitoring for anomalous API calls originating from administrative accounts that lack corresponding multi-factor authentication events in the audit logs.
3. Audit current administrative sessions for signs of unauthorized access, specifically looking for token-based authentication patterns that deviate from standard browser-based login workflows.
