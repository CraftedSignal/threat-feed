---
title: SQL Injection Vulnerability in node-sql-query
slug: 2026-08-node-sql-query-sqli
description: A SQL injection vulnerability in the SelectQuery component of the node-sql-query library allows remote attackers to execute arbitrary SQL commands via manipulated request parameters.
date: "2026-08-09T13:45:36Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - dresende
products:
  - node-sql-query (0.1.25, 0.1.26, 0.1.27, 0.1.28)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: It is possible to initiate the attack remotely.
    confidence_band: high
cves:
  - id: CVE-2026-19351
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-19351
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Upgrade node-sql-query to 0.1.29
      owner: IT Operations
      due: 48h
      evidence: Upgrading to version 0.1.29 addresses this issue.
  mitigation_plan:
    - priority: immediate
      action: Upgrade vulnerable library to 0.1.29
      owner: IT Operations
      addresses: CVE-2026-19351
      evidence: Upgrading to version 0.1.29 addresses this issue.
---

The node-sql-query library (versions 0.1.25 through 0.1.28) contains a critical SQL injection vulnerability within its 'SelectQuery.from' and 'SelectQuery.build' functions in 'lib/Select.js'. The flaw resides in the library's Request Parameter Handler, which fails to properly sanitize input before incorporating it into SQL queries. This allows a remote, unauthenticated attacker to manipulate request parameters to inject malicious SQL syntax into database operations. The vulnerability has been publicly disclosed with a proof-of-concept exploit, posing a significant risk to applications relying on this library for database interaction. Developers are strongly encouraged to upgrade to version 0.1.29, which addresses the issue via the patch '3414c42f6de89826fa1f5f36f6139d1e6552778e'.

## Impact

Successful exploitation of this vulnerability enables attackers to perform unauthorized database operations, including data exfiltration, modification, or deletion. Depending on the database permissions and application configuration, this could lead to full database compromise, unauthorized access to sensitive user data, and potential remote code execution on the underlying database server. 

## Recommendation

- Upgrade the 'node-sql-query' dependency to version 0.1.29 or higher across all development, staging, and production environments.
- Review database logs for suspicious query patterns characterized by unexpected union selects, comment characters, or tautologies originating from the application layer.
- Implement parameterized queries or an object-relational mapping (ORM) layer that enforces strict input validation for all database interactions to mitigate the impact of similar SQL injection vulnerabilities.
