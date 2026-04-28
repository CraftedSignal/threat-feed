---
title: ResourceSpace 8.6 SQL Injection Vulnerability (CVE-2019-25693)
slug: 2026-04-resourcespace-sqli
description: ResourceSpace 8.6 is vulnerable to SQL injection, allowing authenticated attackers to execute arbitrary SQL queries and extract sensitive data by injecting malicious code through the keywords parameter in collection_edit.php.
date: "2026-04-12T13:16:32Z"
severities:
  - high
tags:
  - sqli
  - cve-2019-25693
  - resourcespace
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2019-25693
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2019-25693
  - https://www.exploit-db.com/exploits/46274
  - https://www.vulncheck.com/advisories/resourcespace-sql-injection-via-collection-edit-php
rules:
  - title: Detect ResourceSpace SQL Injection Attempt
    description: Detects potential SQL injection attempts against the ResourceSpace application by monitoring POST requests to collection_edit.php with SQL keywords in the keywords parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect ResourceSpace SQL Injection via Error Messages
    description: Detects potential SQL injection exploitation by identifying error messages in web server logs associated with collection_edit.php.
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

ResourceSpace 8.6 is susceptible to an SQL injection vulnerability (CVE-2019-25693) that can be exploited by authenticated attackers. The vulnerability resides in the `collection_edit.php` script, specifically within the handling of the `keywords` parameter. By crafting malicious SQL payloads within a POST request to this script, an attacker can inject arbitrary SQL queries into the application's database interactions. Successful exploitation enables the attacker to extract sensitive information such as database schema names, user credentials, and other confidential data stored within the ResourceSpace database. The vulnerability was reported and disclosed in April 2026. This poses a significant risk to organizations using vulnerable versions of ResourceSpace, potentially leading to data breaches and unauthorized access to sensitive information.

## Attack Chain

1. An attacker authenticates to the ResourceSpace application with valid user credentials.
2. The attacker identifies the `collection_edit.php` endpoint as a potential target for SQL injection.
3. The attacker crafts a malicious SQL payload designed to extract sensitive information. This payload is injected into the `keywords` parameter of a POST request.
4. The attacker sends the crafted POST request to the `collection_edit.php` endpoint.
5. The application processes the request, and due to the SQL injection vulnerability, the malicious SQL payload is executed against the database.
6. The database returns the results of the injected SQL query, which may include sensitive information like schema details or user credentials.
7. The attacker captures the database response, extracting the injected SQL query results.
8. The attacker uses the extracted information to further compromise the system, potentially gaining unauthorized access to additional resources or escalating privileges. The final objective is typically data exfiltration or complete system takeover.

## Impact

Successful exploitation of this SQL injection vulnerability can lead to the disclosure of sensitive information stored within the ResourceSpace database. This includes database schema details, user credentials (usernames and password hashes), and potentially other confidential data related to the organization's assets managed within ResourceSpace. The number of potential victims is dependent on the number of organizations utilizing the vulnerable ResourceSpace 8.6 software. Exploitation could lead to data breaches, unauthorized access, and potential financial or reputational damage.

## Recommendation

*   Apply appropriate input validation and sanitization to the `keywords` parameter in `collection_edit.php` to prevent SQL injection attacks (CVE-2019-25693).
*   Deploy the Sigma rule `Detect ResourceSpace SQL Injection Attempt` to your SIEM to identify potential exploitation attempts.
*   Monitor web server logs for POST requests to `collection_edit.php` containing suspicious characters or SQL keywords in the `keywords` parameter to proactively identify and block malicious activity.
