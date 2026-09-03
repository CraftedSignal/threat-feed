---
title: CVE-2026-85388 SQL Injection in Worklenz
slug: 2026-09-worklenz-sql-injection
description: Authenticated attackers can exploit improper validation of the sort-field parameter in Worklenz <= 3.0.0 to perform blind SQL injection against PostgreSQL backends.
date: "2026-09-03T19:22:47Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:worklenz:worklenz:*:*:*:*:*:*:*:*
tags:
  - sqli
  - web-vulnerability
  - injection
vendors:
  - Worklenz
products:
  - Worklenz (<= 3.0.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Worklenz through 3.0.0 fails to properly validate the sort-field query parameter in pagination helper functions, allowing authenticated users to inject arbitrary PostgreSQL expressions into ORDER BY clauses.
    confidence_band: high
cves:
  - id: CVE-2026-85388
    cvss: 8.1
  - id: CVE-2026-25947
    cvss: 8.8
    epss: 0.00354
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-85388
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Worklenz instances to a version beyond 3.0.0
      owner: IT Operations
      due: 48h
      evidence: Source identifies vulnerability in versions <= 3.0.0
  enrichment_needed:
    - item: Exploit pattern confirmation
      owner: CTI
      reason: Need to understand specific query patterns to tune detection
      evidence: Lack of specific payload examples in source
  mitigation_plan:
    - priority: immediate
      action: Upgrade Worklenz to 2.1.7 or later
      owner: IT Operations
      addresses: CVE-2026-85388
      evidence: Source reporting of incomplete fix for CVE-2026-25947
---

Worklenz versions 3.0.0 and earlier contain a critical vulnerability in the pagination helper functions that fail to properly sanitize the 'sort-field' query parameter. This oversight allows authenticated users to inject arbitrary PostgreSQL expressions directly into ORDER BY clauses. The flaw serves as an incomplete fix for a previously identified vulnerability, CVE-2026-25947. Attackers can leverage this SQL injection (SQLi) vector to execute time-based or boolean-based blind injection attacks. By manipulating the database queries, unauthorized users can exfiltrate sensitive information, including password hashes from other tenants in a multi-tenant environment. Given the application's reliance on PostgreSQL, the impact is significant for organizations housing sensitive data within Worklenz instances. Defenders must prioritize upgrading to a version that addresses this improper input validation and review application logs for anomalous query parameter patterns.

## Impact

Successful exploitation allows authenticated users to bypass data isolation and extract sensitive database contents. This impacts the confidentiality of all tenant data managed by the Worklenz instance, including credentials, which could lead to further unauthorized access or account takeover across the platform.

## Recommendation

- Upgrade Worklenz to a version beyond 3.0.0 that contains the complete fix for CVE-2026-85388.
- Review web server access logs for anomalous characters or SQL keywords (e.g., CASE, WHEN, THEN, SLEEP, SELECT, UNION) within the 'sort-field' query parameter.
- Apply the principle of least privilege to the Worklenz database user account to restrict access to system tables or sensitive metadata.
