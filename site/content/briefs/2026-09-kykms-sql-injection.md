---
title: SQL Injection Vulnerability in mahonelau kykms
slug: 2026-09-kykms-sql-injection
description: A SQL injection vulnerability in the QueryGenerator.doMultiFieldsOrder function of mahonelau kykms allows remote attackers to execute arbitrary database queries via the column argument.
date: "2026-09-29T16:28:33Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
cpes:
  - cpe:2.3:a:mahonelau:kykms:*:*:*:*:*:*:*:*
tags:
  - web-vulnerability
  - sql-injection
  - vulnerability
vendors:
  - mahonelau
products:
  - kykms (up to 8f130c2d85842d5b44caae78cc46d65e505949f7)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The manipulation of the argument column leads to sql injection. Remote exploitation of the attack is possible.
    confidence_band: high
cves:
  - id: CVE-2026-102491
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-102491
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Audit applications for kykms library usage and identify affected systems
      owner: IT Operations
      due: 48h
      evidence: Source identifies library as the vector for CVE-2026-102491
  mitigation_plan:
    - priority: immediate
      action: Deploy WAF rules to inspect and block malicious SQL syntax in requests containing the column parameter
      owner: SOC
      addresses: CVE-2026-102491
      evidence: Publicly available exploit exists for this vulnerability
  gaps:
    - Lack of vendor-provided patch requires compensating controls
---

A SQL injection vulnerability has been identified in the kykms project maintained by mahonelau, specifically affecting all versions up to commit 8f130c2d85842d5b44caae78cc46d65e505949f7. The vulnerability exists within the QueryGenerator.doMultiFieldsOrder function inside the SqlInjectionUtil.java file. An attacker can manipulate the column argument to inject malicious SQL commands, enabling unauthorized interaction with the underlying database. The vulnerability is remotely exploitable, and proof-of-concept exploit code is publicly available, increasing the risk of active exploitation. The project utilizes a rolling release model, and no specific patch version has been issued by the vendor to address this flaw. Defenders should prioritize identifying instances of this component and implementing input validation controls.

## Impact

Successful exploitation allows remote attackers to execute arbitrary SQL queries against the database used by the kykms component. This can lead to unauthorized data exfiltration, modification of database contents, or potential service disruption. Given the availability of public exploit code, systems utilizing this library are at a high risk of compromise.

## Recommendation

- Perform an inventory of all applications within the environment to identify any software integrating the mahonelau kykms library.
- Monitor web application logs for suspicious characters (e.g., single quotes, semicolons, comment operators) within the column parameter targeting endpoints that utilize the QueryGenerator functionality.
- Implement strict input validation and parameterized queries for all database interactions to mitigate the impact of potential SQL injection vectors.
- Since the vendor has not provided a patched version, consider implementing a Web Application Firewall (WAF) rule to inspect and block malicious payloads targeting the specific vulnerable argument.
