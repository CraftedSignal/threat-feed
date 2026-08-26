---
title: SQL Injection Vulnerability in Simple Online Food Ordering System
slug: 2026-08-simple-food-sql-injection
description: A SQL injection vulnerability in SourceCodester Simple Online Food Ordering System version 1.0 allows unauthenticated remote attackers to manipulate database queries via the email parameter in /admin/ajax.php.
date: "2026-08-26T23:32:21Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - SourceCodester
products:
  - Simple Online Food Ordering System (1.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The manipulation of the argument email leads to sql injection.
    confidence_band: high
cves:
  - id: CVE-2026-81203
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-81203
rules:
  - title: Detects CVE-2026-81203 Exploitation - SQL Injection in admin ajax.php
    description: Detects exploitation of CVE-2026-81203 where an attacker injects SQL syntax into the email parameter of the login2 action
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
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Restrict access to /admin/ajax.php
      owner: IT Operations
      due: 24h
      evidence: Public exploit availability
  mitigation_plan:
    - priority: immediate
      action: Patch or implement WAF rule for CVE-2026-81203
      owner: IT Operations
      addresses: CVE-2026-81203
      evidence: Vulnerability reported in NVD
---

A SQL injection vulnerability, identified as CVE-2026-81203, exists within the admin module of the SourceCodester Simple Online Food Ordering System version 1.0. The vulnerability is located in the /admin/ajax.php file, specifically within the login2 action. Attackers can reach this endpoint remotely and perform malicious manipulation of the email argument. Because this flaw allows for arbitrary SQL command execution, it can potentially lead to unauthorized data exfiltration, modification of database contents, or authentication bypass. The vulnerability has been disclosed publicly, making it available for exploitation. Organizations using this system should restrict access to the /admin/ directory and validate all inputs against the application logic.

## Impact

Successful exploitation of this vulnerability allows an unauthenticated remote attacker to execute arbitrary SQL commands against the backend database. This may result in full compromise of the application data, administrative account takeovers, or further exploitation of the underlying database server, depending on the privileges assigned to the database user.

## Recommendation

* Restrict network access to the /admin/ directory using firewall or web application firewall rules to prevent unauthorized remote requests.
* Apply input sanitization and parameterization to the 'email' argument within /admin/ajax.php to mitigate SQL injection vectors.
* Audit database logs for anomalous queries originating from the /admin/ajax.php endpoint.
