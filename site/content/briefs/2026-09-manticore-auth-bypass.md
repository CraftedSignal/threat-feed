---
title: Manticore Search Multi-Statement Authorization Bypass
slug: 2026-09-manticore-auth-bypass
description: Manticore Search versions 27.0.0 through 28.4.3 contain an authorization vulnerability that allows authenticated read-only users to execute unauthorized SQL statements by appending malicious queries to multi-statement requests.
date: "2026-09-16T23:52:13Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:manticoresearch:manticore_search:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - sql-injection
  - manticore
vendors:
  - Manticore Search
products:
  - Manticore Search (27.0.0 - 28.4.3)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1505
    technique_name: Server Software Component
    evidence: An authenticated read-only user can leverage this to execute unauthorized queries, specifically by appending SELECT statements to read sensitive credential tables, leading to the exposure of administrator password hashes.
    confidence_band: high
cves:
  - id: CVE-2026-92796
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-92796
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade Manticore Search to version 28.4.4
      owner: IT Operations
      due: 48h
      evidence: Vendor patch availability for CVE-2026-92796
  mitigation_plan:
    - priority: immediate
      action: Upgrade to 28.4.4
      owner: IT Operations
      addresses: CVE-2026-92796
      evidence: NVD vulnerability disclosure
---

Manticore Search versions 27.0.0 through 28.4.3 contain an authorization vulnerability (CVE-2026-92796) where the application fails to correctly validate permissions for secondary statements within multi-statement SQL requests. An attacker with low-privileged, read-only access can exploit this flaw by appending additional SQL statements to a legitimate query. The underlying database engine processes the entire multi-statement request without re-verifying authorization for the secondary statements. This allows an attacker to bypass access controls and perform unauthorized read operations, specifically targeting sensitive internal credential tables to extract administrator password hashes. Successful exploitation allows for privilege escalation via hash cracking or credential reuse, enabling full administrative control over the Manticore Search instance. Defenders should prioritize updating to version 28.4.4 or later.

## Impact

The vulnerability results in unauthorized access to sensitive data within the Manticore Search cluster. An attacker who successfully exfiltrates administrator password hashes can potentially gain full administrative access to the search service, leading to full data exposure or service disruption. This vulnerability affects any environment utilizing Manticore Search 27.0.0 through 28.4.3, regardless of the underlying operating system.

## Recommendation

* Upgrade Manticore Search to version 28.4.4 or later to remediate CVE-2026-92796.
* Audit logs for suspicious, multi-statement SQL queries originating from read-only user accounts.
* Implement strict access control lists (ACLs) for database service accounts to limit the blast radius of compromised low-privileged credentials.
