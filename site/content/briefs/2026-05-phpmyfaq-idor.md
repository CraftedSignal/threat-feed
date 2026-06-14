---
title: phpMyFAQ Insecure Direct Object Reference Allows Privilege Escalation (CVE-2026-35671)
slug: 2026-05-phpmyfaq-idor
description: phpMyFAQ before 4.1.3 contains an insecure direct object reference vulnerability in the admin API user password endpoint that allows authenticated administrators to change any user's password without authorization verification, leading to privilege escalation.
date: "2026-05-28T16:18:03Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - idor
  - privilege-escalation
  - web-application
vendors:
  - phpMyFAQ
products:
  - phpMyFAQ < 4.1.3
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-35671
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-35671
  - CVE-2026-35671
rules:
  - title: Detect CVE-2026-35671 Exploitation - phpMyFAQ Password Overwrite Attempt
    description: Detects CVE-2026-35671 exploitation - attempts to overwrite user passwords via the phpMyFAQ admin API without proper authorization.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
  - title: Detect CVE-2026-35671 Exploitation - phpMyFAQ Admin API Access
    description: Detects CVE-2026-35671 exploitation - monitor access to phpMyFAQ admin API endpoints which may indicate potential exploitation of IDOR vulnerabilities.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
rules_count: 2
---

phpMyFAQ before 4.1.3 is vulnerable to an insecure direct object reference (IDOR) flaw within its admin API. This vulnerability allows an authenticated administrator with low privileges to escalate their privileges to SuperAdmin. The vulnerability resides in the user password overwrite endpoint. By manipulating the `userId` parameter during an API request to overwrite a password, a low-privilege administrator can change the password of any other user, including a SuperAdmin account. This can lead to complete control of the phpMyFAQ instance.

## Attack Chain

1. Attacker authenticates to phpMyFAQ as a low-privilege administrator.
2. Attacker identifies the `overwrite-password` API endpoint.
3. Attacker crafts a malicious API request to the `overwrite-password` endpoint, modifying the `userId` parameter to target a SuperAdmin account.
4. The API request bypasses authorization checks and allows the attacker to set a new password for the targeted SuperAdmin account.
5. Attacker uses the newly set password to authenticate as the SuperAdmin.
6. Attacker gains full administrative control over the phpMyFAQ instance.

## Impact

Successful exploitation of this vulnerability allows a low-privilege administrator to gain SuperAdmin access, leading to a complete compromise of the phpMyFAQ instance. This could result in unauthorized data access, modification, or deletion, as well as the potential for further malicious activities within the affected system. This vulnerability affects phpMyFAQ installations prior to version 4.1.3.

## Recommendation

*   Upgrade phpMyFAQ to version 4.1.3 or later to patch CVE-2026-35671.
*   Deploy the Sigma rules provided below to detect potential exploitation attempts targeting the `overwrite-password` API endpoint.
