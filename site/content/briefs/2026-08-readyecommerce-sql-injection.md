---
title: Unauthenticated SQL Injection in ReadyEcommerce Product API
slug: 2026-08-readyecommerce-sql-injection
description: ReadyEcommerce versions before 4.5.2 are vulnerable to unauthenticated time-based blind SQL injection in the product listing API, allowing attackers to exfiltrate database contents and potentially gain system-level access.
date: "2026-08-10T15:31:27Z"
type: advisory
types:
  - advisory
severities:
  - critical
vendors:
  - ReadyEcommerce
products:
  - ReadyEcommerce (< 4.5.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: ReadyEcommerce before 4.5.2 contains an unauthenticated SQL injection vulnerability in the product listing API.
    confidence_band: high
cves:
  - id: CVE-2026-63106
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-63106
rules:
  - title: Detect CVE-2026-63106 - SQL Injection in Product API
    description: Detects potential SQL injection attempts targeting the ReadyEcommerce product listing API via the rating parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Patch all instances of ReadyEcommerce to version 4.5.2 or later.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-63106 remediation requirement
---

ReadyEcommerce versions prior to 4.5.2 contain a critical unauthenticated SQL injection vulnerability in the product listing API. The vulnerability originates in `ProductController.php`, where the `rating` parameter is concatenated directly into a MySQL `HAVING` clause without proper parameterization. This flaw allows unauthenticated remote attackers to execute arbitrary SQL queries against the underlying database via time-based blind SQL injection techniques. Given the reported configuration where the database service runs with root privileges, successful exploitation may lead to full database compromise, extraction of sensitive user credentials and administrator password hashes, and potential file system access. This vulnerability poses a severe risk to the confidentiality and integrity of the affected e-commerce environments.

## Impact

Successful exploitation allows for the full extraction of database contents, including user credentials and administrative password hashes. Due to the database running with root privileges, there is a risk of escalation to unauthorized file system access on the host server.

## Recommendation

* Update ReadyEcommerce to version 4.5.2 or later to remediate the vulnerability in `ProductController.php`.
* Implement input validation and parameterized queries to prevent SQL injection in the product listing API.
* Audit database service configurations to ensure that the database process runs with the least privilege necessary rather than root.
* Monitor webserver access logs for anomalous `POST` or `GET` requests to the product listing endpoint containing SQL syntax or time-delay functions (e.g., `SLEEP()`, `BENCHMARK()`).
