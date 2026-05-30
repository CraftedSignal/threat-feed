---
title: AiOPMSD Final 1.0.0 Unauthenticated SQL Injection Vulnerability (CVE-2018-25414)
slug: 2026-05-aiopmsd-sql-injection
description: AiOPMSD Final 1.0.0 is vulnerable to SQL injection (CVE-2018-25414), allowing unauthenticated attackers to execute arbitrary SQL queries by injecting malicious code through the actor parameter, leading to sensitive data extraction.
date: "2026-05-30T16:19:41Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sql-injection
  - vulnerability
  - web-application
products:
  - AiOPMSD Final
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2018-25414
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2018-25414
rules:
  - title: Detect CVE-2018-25414 Exploitation — AiOPMSD SQL Injection Attempt
    description: Detects CVE-2018-25414 exploitation — attempts to exploit the SQL injection vulnerability in AiOPMSD Final 1.0.0 by detecting suspicious GET requests to `actor.php` with potential SQL injection payloads in the `actor` parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect CVE-2018-25414 Exploitation — AiOPMSD SQL Injection - Error Based
    description: Detects CVE-2018-25414 exploitation — attempts to trigger SQL errors using the actor parameter in AiOPMSD Final 1.0.0.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

AiOPMSD Final version 1.0.0 is susceptible to SQL injection attacks. This vulnerability, identified as CVE-2018-25414, allows unauthenticated remote attackers to inject malicious SQL queries via the 'actor' parameter in HTTP GET requests. Successful exploitation enables attackers to extract sensitive information directly from the application database. The lack of authentication required to trigger the vulnerability makes it particularly dangerous for internet-facing AiOPMSD deployments. The impact includes potential disclosure of database usernames, database names, and underlying version details, potentially aiding in further compromise of the system.

## Attack Chain

1. The attacker identifies a publicly accessible AiOPMSD Final 1.0.0 instance.
2. The attacker crafts a malicious SQL injection payload. This payload targets the `actor` parameter in a GET request to `actor.php`.
3. The attacker sends the crafted GET request to the `actor.php` endpoint.
4. The vulnerable application fails to properly sanitize the input provided via the `actor` parameter.
5. The application executes the attacker-controlled SQL query against the database.
6. The database returns sensitive information, such as usernames, database names, or version details.
7. The attacker receives the database response containing the extracted information.
8. The attacker uses the extracted information to further compromise the system, such as gaining unauthorized access or escalating privileges.

## Impact

Successful exploitation of this SQL injection vulnerability (CVE-2018-25414) in AiOPMSD Final 1.0.0 can lead to the unauthorized disclosure of sensitive database information. This includes usernames, database names, and version details. The CVSS v3.1 base score for this vulnerability is 8.2, indicating a high severity. The extracted information can be used to further compromise the system, potentially leading to data breaches, account takeovers, or other malicious activities. The lack of authentication means any exposed instance is vulnerable.

## Recommendation

*   Apply available patches or upgrades to AiOPMSD to address the SQL injection vulnerability.
*   Deploy the Sigma rule `Detect CVE-2018-25414 Exploitation — AiOPMSD SQL Injection Attempt` to monitor for exploitation attempts targeting the `actor.php` endpoint.
*   Implement input validation and sanitization on all user-supplied input, especially the `actor` parameter, to prevent SQL injection attacks.
*   Enable webserver logging and monitor for suspicious GET requests to the `actor.php` endpoint containing SQL syntax.
