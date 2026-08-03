---
title: Authorization Bypass Vulnerability in Menulux Mobile App
slug: 2026-08-menulux-auth-bypass
description: CVE-2026-2346 is a critical authorization bypass vulnerability (CWE-639) in the Menulux Mobile App allowing unauthenticated attackers to manipulate user-controlled keys and compromise software integrity.
date: "2026-08-03T14:03:21Z"
type: advisory
types:
  - advisory
severities:
  - critical
vendors:
  - Menulux Software Inc.
products:
  - Mobile App (<= 2026-05-12)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Authorization bypass through User-Controlled key vulnerability in Menulux Software Inc. Mobile App allows Software Integrity Attack.
    confidence_band: high
cves:
  - id: CVE-2026-2346
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-2346
  - https://siberguvenlik.gov.tr/guvenlik-bildirimleri/detay/tr-26-0729
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Inventory all mobile devices running Menulux Mobile App version 12.05.2026 or earlier
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-2346 vulnerability scope
  mitigation_plan:
    - priority: immediate
      action: Upgrade Menulux Mobile App to the latest patched version provided by the vendor
      owner: IT Operations
      addresses: CVE-2026-2346
      evidence: NVD vulnerability mitigation guidance
---

CVE-2026-2346 is a critical vulnerability identified in the Menulux Mobile App, documented by the Computer Emergency Response Team of the Republic of Turkey. The flaw involves an authorization bypass mechanism based on a user-controlled key (CWE-639). This vulnerability allows an unauthenticated, remote attacker to bypass existing security controls within the application. By manipulating the user-controlled key, an attacker can achieve unauthorized access or perform actions that impact the integrity of the software. The issue affects all versions of the Menulux Mobile App up to and including the version released on May 12, 2026. Given the CVSS 3.1 base score of 9.8, this vulnerability poses a significant risk to the security and operational integrity of the affected mobile environments.

## Impact

Successful exploitation of this vulnerability results in a complete authorization bypass, enabling attackers to perform unauthorized actions within the application context. This may lead to unauthorized data access, modification of application settings, or a broader software integrity attack. Organizations utilizing the affected version of the Menulux Mobile App are at risk of unauthorized administrative or user-level actions, which could compromise the entire deployment.

## Recommendation

* Immediately audit all instances of the Menulux Mobile App within the environment and identify versions released on or before May 12, 2026.
* Contact Menulux Software Inc. to obtain the latest security updates and patches that address CVE-2026-2346.
* Restrict network access to mobile devices running the vulnerable application if patching cannot be performed immediately.
* Monitor for any anomalous API calls or unauthorized privilege escalation events associated with mobile device communication to backend services.
