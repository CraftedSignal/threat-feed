---
title: MikroORM SQL Injection Vulnerability
slug: 2024-01-mikroorm-sqli
description: MikroORM versions 6.6.9 and 7.0.5 are vulnerable to SQL injection when specially crafted objects are interpreted as raw SQL query fragments, potentially allowing attackers to execute arbitrary SQL commands.
date: "2024-01-30T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - mikroorm
  - sqli
  - sql-injection
  - cve-2026-34220
vendors:
  - MikroORM
products:
  - MikroORM
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-gwhv-j974-6fxm
rules:
  - title: Detect MikroORM SQL Injection Attempt via Native Query
    description: Detects potential SQL injection attempts in MikroORM applications by monitoring for suspicious keywords in native query parameters.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect MikroORM SQL Injection Attempt via POST parameters
    description: Detects potential SQL injection attempts in MikroORM applications by monitoring for suspicious keywords in POST parameters.
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

MikroORM, a TypeScript ORM for Node.js, is susceptible to SQL injection attacks in versions 6.6.9 and earlier, and 7.0.5 and earlier. This vulnerability, identified as CVE-2026-34220, stems from insufficient validation of user-supplied input when constructing database queries. Specifically, specially crafted objects can be misinterpreted as raw SQL fragments, leading to unintended code execution. The attack surface lies in ORM write APIs, particularly those that directly process user-provided data without proper sanitization. Defenders should prioritize patching or implementing input validation to mitigate this risk. This vulnerability can lead to data breaches, unauthorized data modification, or complete database compromise.

## Attack Chain

1. An attacker identifies an application using a vulnerable version of MikroORM (<= 6.6.9 or <= 7.0.5).
2. The attacker locates an API endpoint that utilizes one of the vulnerable MikroORM methods: `wrap(entity).assign(userInput)`, `em.nativeUpdate()`, `em.nativeInsert()`, or `em.create()`.
3. The attacker crafts a malicious object containing SQL injection payloads designed to exploit the lack of input validation. This payload is structured to be misinterpreted as raw SQL.
4. The attacker sends a request to the API endpoint, embedding the crafted malicious object within the `userInput` or other relevant data parameter.
5. The MikroORM framework processes the request, failing to properly sanitize the incoming data. The crafted object is treated as a raw SQL fragment.
6. The malicious SQL fragment is incorporated into the database query executed by MikroORM.
7. The database executes the injected SQL code, potentially allowing the attacker to read, modify, or delete data, or even execute arbitrary system commands depending on database privileges.
8. The attacker achieves unauthorized access to sensitive data, elevates privileges, or compromises the entire application and underlying database server.

## Impact

Successful exploitation of this SQL injection vulnerability allows attackers to execute arbitrary SQL queries against the affected database. This can lead to the disclosure of sensitive data, modification or deletion of critical information, or even complete compromise of the database server. While the exact number of affected applications is unknown, any application utilizing vulnerable versions of MikroORM and failing to properly sanitize user input is at risk. This vulnerability has a critical severity rating due to the potential for widespread and severe impact on data confidentiality, integrity, and availability.

## Recommendation

*   Upgrade MikroORM to version 6.6.10 or later, or 7.0.6 or later, to address the vulnerability (Affected Packages).
*   Implement robust input validation and sanitization measures on all user-supplied data before passing it to MikroORM APIs (Overview).
*   Deploy the Sigma rule "Detect MikroORM SQL Injection Attempt via Native Query" to identify potential exploitation attempts (Rules).
*   Review and harden database access controls to limit the potential impact of successful SQL injection attacks (Attack Chain).
*   Monitor web server logs for suspicious activity related to MikroORM endpoints (Rules).
