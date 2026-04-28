---
title: PraisonAI SQL Injection Vulnerability (CVE-2026-34934)
slug: 2026-04-praisonai-sqli
description: A SQL Injection vulnerability exists in PraisonAI versions prior to 4.5.90, where an attacker can inject malicious SQL code via thread IDs, leading to arbitrary code execution and full database access.
date: "2026-04-04T12:00:00Z"
severities:
  - critical
tags:
  - cve-2026-34934
  - sql-injection
  - praisonai
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-34934
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34934
  - https://github.com/MervinPraison/PraisonAI/security/advisories/GHSA-9cq8-3v94-434g
rules:
  - title: Detect SQL Injection Attempts via User Agent
    description: Detects potential SQL injection attempts in HTTP requests by analyzing the User-Agent header for common SQL keywords.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect SQL Injection in HTTP Query Parameters
    description: Detects potential SQL injection attempts in HTTP requests by analyzing the query parameters for common SQL keywords.
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

PraisonAI, a multi-agent teams system, is vulnerable to SQL Injection in versions prior to 4.5.90 (CVE-2026-34934). The vulnerability lies within the `get_all_user_threads` function, which constructs raw SQL queries using f-strings with unescaped thread IDs fetched directly from the database. This allows an attacker to inject malicious code into the thread ID via the `update_thread` function. When the application subsequently loads the thread list, the injected SQL payload executes, potentially granting the attacker full access to the database. The vulnerability was patched in PraisonAI version 4.5.90. Successful exploitation allows for complete compromise of the application database and sensitive data.

## Attack Chain

1. The attacker identifies a vulnerable PraisonAI instance running a version prior to 4.5.90.
2. The attacker utilizes the `update_thread` function to modify a thread ID.
3. The attacker injects a malicious SQL payload into the thread ID field (e.g., `'; DROP TABLE users; --`).
4. The vulnerable application stores the attacker's crafted thread ID in the database.
5. A legitimate user or application component triggers the `get_all_user_threads` function to load thread data.
6. The `get_all_user_threads` function constructs a raw SQL query using an f-string that incorporates the attacker-controlled, unescaped thread ID directly from the database.
7. The injected SQL code is executed against the database due to the SQL Injection vulnerability.
8. The attacker gains full database access, potentially exfiltrating sensitive information, modifying data, or performing other malicious activities.

## Impact

Successful exploitation of this SQL Injection vulnerability (CVE-2026-34934) allows an attacker to gain complete control over the PraisonAI application's database. This may include exfiltrating sensitive user data, modifying application configurations, or even disrupting the application's availability by deleting critical data. Given the nature of multi-agent systems, successful attacks could expose sensitive data from multiple integrated systems.

## Recommendation

*   Upgrade all PraisonAI instances to version 4.5.90 or later to patch CVE-2026-34934.
*   Implement parameterized queries or prepared statements in all database interactions to prevent SQL Injection attacks.
*   Deploy the Sigma rules below to your SIEM to detect potential exploitation attempts.
*   Review and audit all code that constructs SQL queries from user-supplied input to identify and remediate similar vulnerabilities.
