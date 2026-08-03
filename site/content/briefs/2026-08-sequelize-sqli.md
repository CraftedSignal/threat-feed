---
title: SQL Injection in Sequelize Oracle Dialect
slug: 2026-08-sequelize-sqli
description: Sequelize v6.37.3 and earlier versions contain a critical SQL injection vulnerability in the Oracle dialect implementation, allowing unauthenticated attackers to bypass input sanitization and execute arbitrary SQL.
date: "2026-08-03T20:47:47Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - web-vulnerability
  - sqli
  - npm
  - cve-2026-69240
products:
  - Sequelize (< 6.37.4)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An attacker can inject arbitrary sql expressions.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-v8fg-2rw7-q452
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Upgrade Sequelize to v6.37.4
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-69240 remediation version
  mitigation_plan:
    - priority: immediate
      action: Validate and sanitize all user-supplied input before passing to Sequelize query objects
      owner: Application Security
      addresses: CVE-2026-69240
      evidence: Source advisory details on input handling
---

Sequelize, a widely used ORM for Node.js, contains a critical SQL injection vulnerability (CVE-2026-69240) affecting the library when configured to use the Oracle database dialect. The vulnerability stems from an insecure implementation of the `escape` function in `sql-string.js`. Specifically, the function checks if an input string begins with the patterns `TO_TIMESTAMP` or `TO_DATE` and returns the input raw if these conditions are met, bypassing the standard quote-escaping logic.

This flaw allows an attacker to inject arbitrary SQL expressions if the application uses unsanitized user input (such as URL parameters) within Sequelize query objects. Because this occurs within the ORM's own escaping logic, the vulnerability is particularly dangerous for applications relying on Sequelize to automatically sanitize database interactions. This vulnerability was addressed in Sequelize v6.37.4.

## Impact

Successful exploitation allows for unauthorized database access, enabling attackers to perform unauthorized data exfiltration, modification, or deletion. Impact is dependent on the application's implementation and the database permissions assigned to the service account executing the SQL queries. Given the nature of SQL injection, this vulnerability poses a high risk to the confidentiality and integrity of any database connected to a vulnerable Sequelize instance.

## Recommendation

- Upgrade the Sequelize package to v6.37.4 or later immediately.
- Audit applications using Sequelize to ensure that they are not accepting arbitrary query parameters directly into the `where` clause without strict type validation or schema-based input sanitization.
- Review database audit logs for anomalous SQL patterns, specifically queries containing `TO_TIMESTAMP` or `TO_DATE` followed by SQL logical operators or comment delimiters (e.g., `--`).
- Deploy application-level WAF rules to detect and block URL parameters containing SQL metacharacters if immediate patching is not possible.
