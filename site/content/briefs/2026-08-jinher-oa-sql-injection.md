---
title: SQL Injection Vulnerability in Jinher OA 1.0
slug: 2026-08-jinher-oa-sql-injection
description: Jinher OA 1.0 is vulnerable to remote SQL injection via the 'httpOID' parameter in a specific attendance approval module, allowing attackers to execute arbitrary database queries.
date: "2026-08-15T20:20:34Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sql-injection
  - vulnerability
  - web-application
vendors:
  - Jinher
products:
  - OA (1.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The exploit has been made available to the public and could be used for attacks.
    confidence_band: high
cves:
  - id: CVE-2026-19905
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-19905
  - https://vuldb.com/vuln/390110
rules:
  - title: Detects CVE-2026-19905 Exploitation - SQL Injection in Jinher OA
    description: Detects exploitation attempts against Jinher OA by monitoring for SQL injection syntax within the httpOID parameter of the attendance_out_approve.aspx endpoint.
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
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma detection rule to web access logs.
      owner: Detection Engineering
      due: 24h
      evidence: Publicly available exploit code for CVE-2026-19905 exists.
  mitigation_plan:
    - priority: immediate
      action: Configure WAF to block common SQL injection strings in /C6/JHSoft.Web.HrmAttendance/attendance_out_approve.aspx.
      owner: IT Operations
      addresses: CVE-2026-19905
      evidence: CVE description confirms vulnerability is triggered via httpOID parameter.
---

A SQL injection vulnerability has been identified in Jinher OA version 1.0, specifically within the '/C6/JHSoft.Web.HrmAttendance/attendance_out_approve.aspx' file. The vulnerability is triggered by the improper neutralization of the 'httpOID' argument, which is directly processed by the application's backend database. This flaw enables unauthenticated remote attackers to inject malicious SQL commands, potentially leading to unauthorized data access, modification, or full compromise of the database backend. Publicly available exploit code has been released for this vulnerability, and the vendor has not provided a patch or a response to the disclosure. Defenders should prioritize auditing web server logs for requests targeting this specific ASPX endpoint containing non-standard or SQL-like syntax within the query parameters.

## Attack Chain

1. Attacker performs reconnaissance to identify the presence of Jinher OA 1.0 web applications.
2. Attacker crafts an HTTP GET or POST request targeting the 'attendance_out_approve.aspx' endpoint.
3. Attacker injects malicious SQL payloads into the 'httpOID' parameter to test for injection vulnerability.
4. The web application's backend server processes the unsanitized input within a database query.
5. The database executes the injected commands, granting the attacker access to or control over data.
6. Attacker exfiltrates sensitive information or escalates privileges within the database environment.

## Impact

Successful exploitation of this vulnerability allows unauthenticated remote attackers to gain unauthorized access to the application's underlying database. This could result in the exfiltration of sensitive organizational data, manipulation of attendance records, or potential further compromise of the web server if the database service account has excessive permissions. Given the public availability of exploit code, the risk of automated scanning and exploitation is high.

## Recommendation

* Deploy the provided Sigma rule to web server access logs to detect potential exploitation attempts targeting the identified endpoint.
* Monitor inbound web traffic for high-frequency or anomalous requests to '/C6/JHSoft.Web.HrmAttendance/attendance_out_approve.aspx'.
* Implement input validation at the web application firewall (WAF) layer to block common SQL injection patterns in the 'httpOID' parameter.
* Restrict network access to the Jinher OA application, exposing it only to necessary internal network segments until the vendor provides a patch.
