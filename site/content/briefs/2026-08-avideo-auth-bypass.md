---
title: Authentication Bypass in AVideo via Parameter Manipulation
slug: 2026-08-avideo-auth-bypass
description: An authentication bypass vulnerability in AVideo (CVE-2026-59808) allows attackers with upload access to hijack administrative sessions via improper video ownership verification.
date: "2026-08-22T15:30:44Z"
lastmod: "2026-08-30T17:11:31Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - authentication-bypass
  - privilege-escalation
  - web-application
  - ssrf
  - vulnerability
  - credential-theft
vendors:
  - AVideo
products:
  - AVideo
  - AVideo (< 24.0)
  - AVideo (<= e01e41ecc)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: useVideoHashOrLogin() converts this hash into passwordless login as the video owner.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1550.002
    technique_name: 'Use Alternate Authentication Material: Pass the Hash'
    evidence: Attackers with upload permission can retrieve an administrator's video_id_hash... then use that hash in an unauthenticated request to gain administrative session access.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Unauthenticated attackers can bypass SSRF protections via the LiveLinks proxy endpoint to reach internal services.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1048
    technique_name: Exfiltration Over Alternative Protocol
    evidence: enabling unauthorized access to internal network resources and cloud metadata services.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552.001
    technique_name: 'Unsecured Credentials: Credentials in Files'
    evidence: The endpoint discloses stream keys and URLs for third-party platforms.
    confidence_band: high
cves:
  - id: CVE-2026-59808
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-59808
  - https://nvd.nist.gov/vuln/detail/CVE-2026-81678
  - https://nvd.nist.gov/vuln/detail/CVE-2026-82645
rules:
  - title: Detect CVE-2026-82645 Exploitation Attempt - Unauthorized Access to GetLiveKey
    description: Detects unauthorized attempts to access the getLiveKey.json.php endpoint by monitoring for anomalous requests that bypass standard authentication flows, specifically targeting the restream credential extraction endpoint.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - initial_access
    techniques:
      - T1552.001
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade AVideo beyond commit 9c39d8c8 to resolve CVE-2026-59808.
      owner: IT Operations
      due: 48h
      evidence: NVD Vulnerability Report
  mitigation_plan:
    - priority: immediate
      action: Monitor administrative session logs for unauthorized passwordless authentication attempts.
      owner: SOC
      addresses: CVE-2026-59808
      evidence: Source describes auth bypass via hash manipulation
updates:
  - at: "2026-08-27T19:10:41Z"
    level: L2
    summary: added coverage for AVideo (< 24.0)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-81678
  - at: "2026-08-30T17:11:31Z"
    level: L2
    summary: 'added detection rule: Detect CVE-2026-82645 Exploitation Attempt - Unauthorized Access to GetLiveKey'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-82645
---

AVideo through commit 9c39d8c8 contains a critical authentication bypass vulnerability due to flawed validation logic within the `deduplicateByEncoderQueueId()` and `useVideoHashOrLogin()` functions. The software fails to perform proper ownership verification when the `videos_id` parameter is omitted during an upload process, causing the system to return a `video_id_hash` belonging to any video, including those owned by administrators. Because the `useVideoHashOrLogin()` function treats this hash as a valid credential for passwordless login, an attacker can leverage a captured hash to authenticate as the video owner. This flaw allows an attacker with low-privileged upload access to escalate privileges to the administrator level, enabling full system configuration control. This vulnerability highlights the risks of implicit trust in video identifier hashes for session management.

## Impact

Successful exploitation allows for full administrative account takeover within an AVideo instance. Attackers can modify system configurations, manage user accounts, and potentially gain access to sensitive media content. This is particularly critical for enterprise or public-facing video platforms where AVideo is used to manage high-privileged administrative accounts.

## Recommendation

* Apply patches or upgrade AVideo instances to a version beyond commit 9c39d8c8 to address the logic error in ownership verification.
* Monitor web server logs for anomalous POST or GET requests to upload endpoints where the `videos_id` parameter is absent or manipulated.
* Audit current AVideo session management logs for unusual passwordless login patterns involving `video_id_hash` parameters.
