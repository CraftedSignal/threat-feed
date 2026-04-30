---
title: GLPI Unauthenticated Time-Based Blind SQL Injection Vulnerability (CVE-2026-26263)
slug: 2026-04-glpi-sql-injection
description: GLPI versions 11.0.0 to before 11.0.6 are susceptible to an unauthenticated time-based blind SQL injection vulnerability in the search engine, allowing remote attackers to potentially extract sensitive information.
date: "2026-04-06T15:17:07Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - sql-injection
  - glpi
  - cve-2026-26263
  - web-application
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-26263
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-26263
  - https://github.com/glpi-project/glpi/security/advisories/GHSA-346p-qj3v-9rxj
rules:
  - title: Detect GLPI SQL Injection Attempt via Search
    description: Detects potential SQL injection attempts against GLPI search functionality based on suspicious keywords in HTTP requests.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect GLPI SQL Injection Attempt via POST Request
    description: Detects potential SQL injection attempts against GLPI search functionality using POST requests.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

GLPI, a widely used free asset and IT management software, is vulnerable to a critical security flaw. Specifically, versions 11.0.0 to before 11.0.6 contain an unauthenticated time-based blind SQL injection vulnerability (CVE-2026-26263) within its search engine functionality. This vulnerability allows remote attackers to inject malicious SQL code without needing prior authentication. Exploitation could lead to unauthorized data access, modification, or deletion, potentially compromising the entire GLPI instance and the sensitive information it manages. The vulnerability was reported on April 6th, 2026 and patched in version 11.0.6. Organizations using affected versions of GLPI should upgrade immediately to mitigate this risk.

## Attack Chain

1. An unauthenticated attacker identifies a GLPI instance running a vulnerable version (11.0.0 to 11.0.5).
2. The attacker crafts a malicious HTTP request targeting the search engine functionality.
3. The crafted request includes a time-based blind SQL injection payload within a search query parameter.
4. The GLPI server processes the malicious SQL query without proper sanitization.
5. The injected SQL code interacts with the database, causing time delays based on conditional logic.
6. The attacker analyzes the response times to infer the results of the injected SQL queries.
7. Through repeated requests, the attacker extracts sensitive data from the database, such as usernames, passwords, or configuration details.
8. The attacker uses the extracted credentials to gain unauthorized access to the GLPI system or other related resources.

## Impact

Successful exploitation of CVE-2026-26263 can lead to complete compromise of the GLPI instance. Attackers can access sensitive IT asset data, user credentials, and system configurations. This can result in data breaches, financial loss, and reputational damage. Given GLPI's widespread use in IT management, a successful attack could impact numerous organizations across various sectors. If exploited, attackers can use the compromised GLPI instance as a pivot point to further compromise the internal network.

## Recommendation

*   Upgrade GLPI to version 11.0.6 or later to patch CVE-2026-26263.
*   Deploy the provided Sigma rule to detect potential exploitation attempts targeting the GLPI search functionality.
*   Monitor web server logs for suspicious requests containing SQL injection payloads, focusing on parameters used by the GLPI search engine.
*   Implement input validation and sanitization measures to prevent SQL injection vulnerabilities in web applications.
*   Regularly review and update web application firewalls (WAFs) with the latest rules to block known SQL injection patterns.
