---
title: Dovecot SQL Authentication Bypass via Misconfigured Username Characters
slug: 2026-03-dovecot-auth-bypass
description: A misconfiguration vulnerability in Dovecot (CVE-2026-24031) allows authentication bypass and user enumeration when the `auth_username_chars` setting is cleared, potentially leading to unauthorized access to mailboxes.
date: "2024-01-25T12:00:00Z"
lastmod: "2026-10-17T00:45:37Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:dovecot:dovecot:*:*:*:*:*:*:*:*
  - cpe:2.3:a:open-xchange:dovecot:*:*:*:*:pro:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-ARAMOSF-CVE-2026-24031&utm_source=rss&utm_medium=rss
tags:
  - dovecot
  - authentication-bypass
  - sql-injection
vendors:
  - Dovecot
  - Open-xchange
products:
  - Dovecot (< 2.4.3)
  - Dovecot (< 3.1.4)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
cves:
  - id: CVE-2026-24031
    cvss: 7.7
    epss: 0.00395
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-24031
  - https://documentation.open-xchange.com/dovecot/security/advisories/csaf/2026/oxdc-adv-2026-0001.json
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-ARAMOSF-CVE-2026-24031&utm_source=rss&utm_medium=rss
rules:
  - title: Detect Dovecot Authentication Attempt with Suspicious Characters
    description: Detects authentication attempts to Dovecot with usernames containing characters outside the standard alphanumeric range, potentially indicating SQL injection attempts if auth_username_chars is misconfigured.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1555
    data_sources:
      - auth
      - dovecot
  - title: Detect Dovecot Configuration File Modification for auth_username_chars
    description: Detects modification of Dovecot configuration files specifically targeting the auth_username_chars setting, which could indicate an attempt to introduce the vulnerability.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - file_event
      - linux
rules_count: 2
updates:
  - at: "2026-10-17T00:45:37Z"
    level: L2
    summary: poc_available; added CVE-2026-24031
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-ARAMOSF-CVE-2026-24031&utm_source=rss&utm_medium=rss
---

CVE-2026-24031 describes an authentication bypass vulnerability affecting Dovecot, an open-source mail server. The vulnerability arises when the `auth_username_chars` setting, which defines the allowed characters in usernames, is cleared by an administrator. Disabling this setting allows for manipulation of SQL queries used for authentication, leading to potential bypass of authentication checks for any user and enabling user enumeration. The vulnerability was reported on March 27, 2026. There is no mention of publicly available exploits. The primary mitigation is to avoid clearing the `auth_username_chars` setting or to update to a patched version of Dovecot.

## Attack Chain

1.  An attacker identifies a Dovecot server with SQL-based authentication.
2.  The attacker discovers that the `auth_username_chars` setting is cleared.
3.  The attacker crafts a malicious username containing SQL injection code.
4.  The attacker attempts to authenticate with the crafted username.
5.  Dovecot processes the username in an SQL query without proper sanitization due to the missing `auth_username_chars` restriction.
6.  The malicious SQL code is executed, bypassing authentication checks.
7.  The attacker gains unauthorized access to a user's mailbox.
8.  The attacker may enumerate valid usernames by manipulating the SQL injection to extract user data.

## Impact

Successful exploitation of CVE-2026-24031 allows attackers to bypass authentication and gain unauthorized access to user mailboxes on affected Dovecot servers. It also enables user enumeration, which can be used in subsequent attacks. The severity of the impact depends on the sensitivity of the information stored in the compromised mailboxes. A CVSS v3.1 score of 7.7 (HIGH) indicates a significant risk.

## Recommendation

*   Ensure the `auth_username_chars` setting in Dovecot is not cleared to prevent SQL injection vulnerabilities as described in CVE-2026-24031.
*   Monitor Dovecot configuration files for changes to the `auth_username_chars` setting using file integrity monitoring rules.
*   Deploy the Sigma rule provided below to detect attempts to authenticate with usernames containing potentially malicious characters based on the expected character set defined by `auth_username_chars`.
*   Upgrade Dovecot to the latest patched version to address this vulnerability and other potential security issues.
