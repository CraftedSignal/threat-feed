---
title: SQL Injection in ILIAS Repository Trash Table
slug: 2026-09-ilias-sql-injection
description: An authenticated SQL injection vulnerability in ILIAS allows users with write permissions to execute stacked queries, leading to unauthorized database access and potential account takeover.
date: "2026-09-04T19:26:48Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:ilias:ilias:*:*:*:*:*:*:*:*
vendors:
  - ILIAS
products:
  - ILIAS (< 9.22, < 10.10, < 11.3)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Authenticated users with write permission on any container can inject arbitrary SQL through the sort parameter.
    confidence_band: high
cves:
  - id: CVE-2026-82538
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-82538
rules:
  - title: Detects CVE-2026-82538 Exploitation - SQL Injection via Repository Sort Parameter
    description: Detects attempts to exploit the SQL injection vulnerability in ILIAS by monitoring for SQL-specific characters in the sort parameter of repository requests.
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
    - Detection Engineering
  immediate_actions:
    - action: Upgrade ILIAS to 9.22, 10.10, or 11.3
      owner: IT Operations
      due: 24h
      evidence: Source states versions below 9.22, 10.10, and 11.3 are vulnerable.
    - action: Deploy Sigma rule for SQL injection patterns
      owner: Detection Engineering
      due: 24h
      evidence: Detection rule provided in this brief.
  mitigation_plan:
    - priority: immediate
      action: Upgrade ILIAS to 9.22 or later
      owner: IT Operations
      addresses: CVE-2026-82538
      evidence: NVD advisory indicates vulnerability is resolved in versions 9.22, 10.10, and 11.3.
---

ILIAS, an open-source learning management system, contains a critical SQL injection vulnerability tracked as CVE-2026-82538. The flaw exists within the repository trash table management functionality. Specifically, the system fails to validate the navigation sort field provided in HTTP requests before incorporating it into the ORDER BY clause of a database query. 

Because the application enables multi-statement execution within its database abstraction layer, an attacker with write permissions on any container can leverage the sort parameter to inject stacked queries. Successful exploitation permits an attacker to perform arbitrary read and write operations against the underlying database. These actions can be used to exfiltrate sensitive data or escalate privileges by modifying administrative account credentials, effectively leading to full platform takeover. This vulnerability affects ILIAS versions prior to 9.22, 10.10, and 11.3.

## Attack Chain

1. Attacker authenticates to the ILIAS platform with at least write-level permissions on any repository container.
2. Attacker navigates to the repository trash table interface.
3. Attacker intercepts the HTTP request containing the navigation sort parameter.
4. Attacker crafts a malicious payload containing stacked SQL queries, such as modifying administrative user hashes or adding a new administrative user.
5. Attacker injects the payload into the sort parameter of the HTTP request.
6. The application passes the unsanitized input directly into the SQL ORDER BY clause.
7. The database driver executes the injected stacked queries alongside the original statement.
8. Attacker gains unauthorized read/write access or elevated privileges resulting in administrator account takeover.

## Impact

Successful exploitation allows authenticated attackers to bypass application-level access controls. By gaining full read and write access to the database, attackers can exfiltrate sensitive user data, modify learning content, or escalate their privileges to administrator status, resulting in total compromise of the learning management system.

## Recommendation

1. Upgrade ILIAS to version 9.22, 10.10, 11.3, or later immediately to remediate CVE-2026-82538.
2. Audit web server logs for HTTP requests to the repository trash table containing atypical characters such as semicolons, comments, or union/select statements in the sort parameter.
3. Restrict administrative and write permissions to only necessary users to reduce the blast radius of potential exploitation.
