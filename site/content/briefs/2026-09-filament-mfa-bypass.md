---
title: Authentication Bypass in Filament Framework MFA
slug: 2026-09-filament-mfa-bypass
description: An improper authentication vulnerability in the Filament framework allows attackers to bypass app-based multi-factor authentication when recovery codes are enabled.
date: "2026-09-02T00:00:24Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:filamentphp:filament:*:*:*:*:*:*:*:*
vendors:
  - FilamentPHP
products:
  - filament (>= 4.0.0, < 4.12.0)
  - filament (>= 5.0.0, < 5.7.0)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1556
    technique_name: Modify Authentication Process
    evidence: A flaw in the challenge handling for app-based multi-factor authentication allows the second factor to be bypassed.
    confidence_band: high
cves:
  - id: CVE-2026-77567
    cvss: 8.1
    epss: 0.00304
references:
  - https://github.com/advisories/GHSA-52xp-w8hr-xv3c
  - https://nvd.nist.gov/vuln/detail/CVE-2026-77567
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Upgrade filament/filament to version 4.12.0 or 5.7.0
      owner: IT Operations
      due: 24h
      evidence: Source explicitly mandates upgrading to these versions to patch CVE-2026-77567.
  mitigation_plan:
    - priority: immediate
      action: Disable app-based MFA or recovery codes
      owner: Application Security
      addresses: CVE-2026-77567
      evidence: Vulnerability is tied to the usage of recovery codes with app-based MFA.
---

Filament, a popular framework for building administrative panels, contains a critical authentication flaw identified as CVE-2026-77567. The vulnerability exists in the challenge handling logic for app-based multi-factor authentication (MFA). When recovery codes are enabled for a user, the application fails to properly validate the second-factor token, allowing an attacker to bypass the MFA challenge entirely. This flaw is specific to app-based MFA and does not affect configurations using email-based authentication. The issue impacts Filament version branches 4.x (prior to 4.12.0) and 5.x (prior to 5.7.0). Successful exploitation grants an attacker unauthorized access to protected accounts, bypassing a significant layer of security intended to prevent account takeover.

## Impact

The vulnerability poses a severe risk to organizations using Filament for administrative interfaces, as it allows unauthorized users with valid primary credentials to bypass the second-factor requirement. This essentially negates the security benefits of MFA for affected users, significantly increasing the likelihood of account compromise, data exfiltration, and unauthorized administrative actions within the application.

## Recommendation

Prioritize patching affected systems to mitigate the risk of account takeover.

- Upgrade the filament/filament package to version 4.12.0 or 5.7.0 immediately.
- Disable app-based MFA or recovery codes as a temporary workaround until patching is complete if the application must remain internet-facing.
- Audit authentication logs for unusual login patterns or failed attempts followed by successful access to user accounts in the administrative panel.
- Review administrative user accounts for unauthorized changes or configuration modifications made since the deployment of vulnerable versions.
