---
title: Piwigo SQL Injection Vulnerability (CVE-2026-27885)
slug: 2026-04-piwigo-sqli
description: CVE-2026-27885 is a SQL Injection vulnerability in Piwigo before version 16.3.0, affecting the Activity List API endpoint, allowing an authenticated administrator to extract sensitive data.
date: "2026-04-03T22:16:26Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - sql-injection
  - web-application
  - piwigo
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-27885
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-27885
  - https://github.com/Piwigo/Piwigo/commit/c172d284e11eab4a5dbadd2844d26f734d5c8c72
  - https://github.com/Piwigo/Piwigo/security/advisories/GHSA-wfmr-9hg8-jh3m
  - https://piwigo.org/release-16.3.0
iocs:
  - type: email
    value: '[email&#160;protected]'
ioc_counts:
  email: 1
rules:
  - title: Detecting SQL Injection Attempts in Piwigo
    description: Detects potential SQL injection attempts targeting Piwigo Activity List API endpoint by looking for common SQL keywords in the request URI.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1595
    data_sources:
      - webserver
      - linux
  - title: Piwigo - Suspicious POST Request to Activity List API
    description: Detects POST requests to the Piwigo Activity List API, which is unusual and may indicate exploitation attempts.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Piwigo is an open-source photo gallery application. A SQL Injection vulnerability, identified as CVE-2026-27885, exists in Piwigo versions prior to 16.3.0. Specifically, the Activity List API endpoint is susceptible. An authenticated administrator, by crafting malicious SQL queries, can exploit this vulnerability to extract sensitive data, including user credentials, email addresses, and all stored content within the Piwigo database. Piwigo versions 16.3.0 and later contain a patch for this vulnerability. This allows attackers to potentially take over the entire Piwigo instance by exploiting the vulnerability and dumping the credentials of other administrators or users. The CVSS v3.1 base score is rated as 7.2 (HIGH).

## Attack Chain

1. An attacker gains administrative access to a Piwigo instance running a version prior to 16.3.0, through either brute-forcing credentials or compromising an existing admin account.
2. The attacker crafts a malicious SQL query designed to exploit the SQL Injection vulnerability in the Activity List API endpoint.
3. The attacker sends a request to the vulnerable Activity List API endpoint with the crafted SQL payload embedded within the request parameters.
4. The Piwigo application processes the request without proper sanitization, executing the malicious SQL query against the database.
5. The database returns the results of the malicious query, which could include sensitive information such as user credentials, email addresses, and other stored data.
6. The attacker captures the database response and extracts the sensitive information.
7. The attacker uses the extracted credentials to elevate privileges or impersonate other users, potentially gaining full control of the Piwigo instance.
8. The attacker exfiltrates sensitive data, defaces the photo gallery, or performs other malicious actions.

## Impact

Successful exploitation of CVE-2026-27885 can lead to complete compromise of a Piwigo instance. An attacker could steal user credentials, modify or delete photos, and potentially use the compromised server as a staging point for further attacks. The number of affected installations is unknown, but any Piwigo instance running a version prior to 16.3.0 is vulnerable if an attacker can get administrative access.

## Recommendation

*   Upgrade Piwigo installations to version 16.3.0 or later to patch CVE-2026-27885.
*   Monitor web server logs for suspicious requests to the Activity List API endpoint that contain potentially malicious SQL syntax to trigger the rule `Detecting SQL Injection Attempts in Piwigo`.
*   Implement strict input validation and sanitization on all user-supplied data to prevent SQL injection vulnerabilities.
