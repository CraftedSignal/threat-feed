---
title: 'CVE-2026-49952: Discuz! X5.0 Authentication Bypass Leading to Database Access'
slug: 2026-06-discuz-auth-bypass
description: CVE-2026-49952 is an authentication bypass vulnerability in Discuz! X5.0 versions 20260320 through 20260501, allowing unauthenticated remote attackers to gain unauthorized access to database backup and restore functionality by exploiting a shared cryptographic key, leading to potential data exfiltration and user impersonation.
date: "2026-06-15T20:19:42Z"
lastmod: "2026-07-24T19:00:31Z"
type: advisory
types:
  - advisory
severities:
  - high
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=E3511389-563B-5AD7-A686-6FA07D46FB08&utm_source=rss&utm_medium=rss
tags:
  - authentication-bypass
  - web-vulnerability
  - cve
  - discuz
  - data-exfiltration
vendors:
  - Discuz!
products:
  - Discuz! X5.0 (20260320 through 20260501)
  - Discuz! X5.0
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: ""
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: ""
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1490
    technique_name: Inhibit System Recovery
cves:
  - id: CVE-2026-49952
    cvss: 9.1
    epss: 0.0135
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-49952
  - https://sploitus.com/exploit?id=E3511389-563B-5AD7-A686-6FA07D46FB08&utm_source=rss&utm_medium=rss
iocs:
  - type: url
    value: https://sploitus.com/exploit?id=E3511389-563B-5AD7-A686-6FA07D46FB08
ioc_counts:
  url: 1
rules:
  - title: Detects CVE-2026-49952 Exploitation - Malicious Username Injection Attempt
    description: Detects CVE-2026-49952 exploitation - Attempts to exploit the authentication bypass by injecting crafted payloads into the username parameter during login, targeting the encryption oracle.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - initial_access
    techniques:
      - T1190
      - T1552.006
    data_sources:
      - webserver
  - title: Detects CVE-2026-49952 Exploitation - Unauthorized dbbak.php Access
    description: Detects CVE-2026-49952 exploitation - Unauthorized or suspicious access attempts to the Discuz! database backup/restore utility (dbbak.php), which could indicate a successful authentication bypass.
    platform: sigma
    severity: high
    tactics:
      - exfiltration
      - impact
      - privilege_escalation
    techniques:
      - T1041
      - T1078
      - T1490
    data_sources:
      - webserver
rules_count: 2
updates:
  - at: "2026-07-24T19:00:31Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=E3511389-563B-5AD7-A686-6FA07D46FB08&utm_source=rss&utm_medium=rss
---

A critical authentication bypass vulnerability, identified as CVE-2026-49952, impacts Discuz! X5.0 releases from 20260320 through 20260501. This flaw allows unauthenticated remote attackers to gain unauthorized access to sensitive database backup and restore functionalities. The vulnerability stems from a shared cryptographic key utilized between the UCenter integration and the `dbbak.php` database backup API. Attackers can leverage an encryption oracle within the `logging_ctl::logging_more()` function by injecting a specially crafted payload via the username parameter during a login attempt. This manipulation enables them to obtain a legitimately signed token, thereby circumventing standard authorization checks for database operations and potentially triggering a race condition to impersonate arbitrary users. This provides a direct path to sensitive data exfiltration and control over forum content.

## Attack Chain

1.  An unauthenticated remote attacker identifies a Discuz! X5.0 instance (releases 20260320-20260501) vulnerable to CVE-2026-49952.
2.  The attacker crafts a malicious payload and injects it into the `username` parameter during a login attempt to the Discuz! instance via a `POST` request to `/member.php` or similar login endpoint.
3.  This crafted payload is processed by the `logging_ctl::logging_more()` function, which contains an encryption oracle due to a shared cryptographic key used by UCenter integration.
4.  By exploiting this encryption oracle, the attacker obtains a legitimately signed authorization token that can bypass further access controls.
5.  The attacker uses the forged token to send direct HTTP requests to the `/dbbak.php` endpoint, bypassing normal authentication and authorization checks.
6.  Through the `/dbbak.php` interface, the attacker gains unauthorized access to initiate database export (backup) and import (restore) operations.
7.  The attacker can additionally trigger a race condition during this process to impersonate arbitrary authenticated users within the Discuz! forum.
8.  The final objective is unauthorized access to critical database functions, allowing for data theft, modification, or complete compromise of the forum's content and user data.

## Impact

Successful exploitation of CVE-2026-49952 grants unauthenticated attackers full control over the Discuz! X5.0 application's database. This includes the ability to export all database contents, leading to mass data exfiltration of user information, private messages, and forum posts. Attackers could also import malicious data, deface the forum, or implant persistent backdoors. The ability to impersonate arbitrary users further exacerbates the risk, allowing attackers to perform actions as legitimate users, including administrative actions if an administrator account is impersonated. Organizations using affected Discuz! X5.0 versions face severe risks of data breach, reputational damage, and operational disruption.

## Recommendation

*   **Patch CVE-2026-49952 immediately** by upgrading Discuz! X5.0 to a version beyond 20260501 that includes the fix.
*   Deploy the provided Sigma rules "Detects CVE-2026-49952 Exploitation - Malicious Username Injection Attempt" and "Detects CVE-2026-49952 Exploitation - Unauthorized dbbak.php Access" to your SIEM to detect exploitation attempts.
*   Enable comprehensive webserver access logging to capture full HTTP request details (URI stem, query, method, user-agent) for your Discuz! instances to facilitate detection and forensics.
