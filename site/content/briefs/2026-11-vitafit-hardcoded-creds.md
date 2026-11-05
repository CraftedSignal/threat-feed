---
brief_id: brief-2026-11-05-vitafit-hardcoded-creds
event_id: brief-2026-11-05-vitafit-hardcoded-creds
revision: 1
activity_at: "2026-11-05T00:07:22Z"
title: 'VitaFit Android: Hardcoded third-party integration credentials (CVE-2026-54374)'
slug: 2026-11-vitafit-hardcoded-creds
description: The VitaFit Android application versions prior to 2.8.1.0 contain hardcoded credentials for WeChat, Tencent QQ, and Fitbit integrations, allowing attackers to extract them via static analysis of the APK.
date: "2026-11-05T00:07:22Z"
lastmod: "2026-11-05T00:07:30Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:vitafit:vitafit:*:*:*:*:*:android:*:*
vendors:
  - VitaFit
products:
  - VitaFit (< 2.8.1.0)
affected_os:
  - Android
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    subtechnique_id: T1552.001
    subtechnique_name: Credentials In Files
    evidence: Attackers can retrieve embedded WeChat, Tencent QQ, and Fitbit credentials from the decompiled application to abuse the active third-party application registrations.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: Attackers can use a stolen session token to read and modify the victim's account or delete the account's authentication record, preventing the legitimate owner from logging in again.
    confidence_band: high
cves:
  - id: CVE-2026-54374
    cvss: 7.5
    kev_status: "false"
  - id: CVE-2026-54375
    cvss: 8.4
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-54374
  - https://nvd.nist.gov/vuln/detail/CVE-2026-54375
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Team
    - Mobile Security Team
  immediate_actions:
    - action: Upgrade VitaFit Android application to version 2.8.1.0 or later.
      owner: Mobile Security Team
      due: 48h
      evidence: VitaFit Android application (com.vt.vitafit) before 2.8.1.0 contains an insecure session management vulnerability.
  hunt_leads:
    - lead: Identify endpoints or mobile devices with vulnerable VitaFit versions installed
      technique_id: T1552.001
      data_needed:
        - Mobile Device Management (MDM) inventory
        - Application version logs
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: VitaFit Android application (com.vt.vitafit) before 2.8.1.0 contains a hardcoded credentials vulnerability
  mitigation_plan:
    - priority: immediate
      action: Upgrade VitaFit to version 2.8.1.0 or later
      owner: IT Operations
      addresses: CVE-2026-54374
      evidence: VitaFit Android application (com.vt.vitafit) before 2.8.1.0 contains a hardcoded credentials vulnerability
    - priority: immediate
      action: Upgrade to version 2.8.1.0
      owner: IT Operations
      addresses: CVE-2026-54375
      evidence: Fixed in 2.8.1.0
updates:
  - at: "2026-11-05T00:07:30Z"
    level: L2
    summary: added coverage for VitaFit (< 2.8.1.0)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-54375
---

The VitaFit Android application (package com.vt.vitafit) before version 2.8.1.0 contains hardcoded credentials for third-party integrations, specifically WeChat, Tencent QQ, and Fitbit. Attackers can decompile the APK to extract these credentials, leading to unauthorized use of the third-party service accounts.

## Impact

Successful exploitation allows for the unauthorized access or misuse of a user's linked WeChat, Tencent QQ, or Fitbit accounts.

## Recommendation

- Update the VitaFit Android application to version 2.8.1.0 or later immediately.
- Revoke any third-party access tokens or credentials associated with WeChat, Tencent QQ, or Fitbit that were configured within VitaFit prior to the update.
- Perform a security review of hardcoded configuration data in mobile application builds during the CI/CD pipeline to prevent credential leakage.
