---
title: PowerJob SQL Injection Vulnerability (CVE-2026-5736)
slug: 2026-04-powerjob-sqli
description: A remote SQL injection vulnerability, CVE-2026-5736, exists in PowerJob versions 5.1.0 through 5.1.2 within the detailPlus Endpoint, potentially allowing unauthenticated attackers to execute arbitrary SQL queries.
date: "2026-04-07T19:16:48Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - sql-injection
  - vulnerability
  - powerjob
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-5736
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5736
  - https://github.com/PowerJob/PowerJob/
  - https://github.com/PowerJob/PowerJob/issues/1167
rules:
  - title: Detect Suspicious PowerJob customQuery Parameter
    description: Detects suspicious requests to the /detailPlus endpoint in PowerJob with potentially malicious SQL injection payloads in the customQuery parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: PowerJob detailPlus Endpoint Access
    description: Detects access to the PowerJob detailPlus endpoint, which may indicate vulnerability scanning or exploitation attempts.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2026-5736 is a SQL injection vulnerability affecting PowerJob, an open-source distributed job scheduling and management platform. The vulnerability resides in the `InstanceController.java` file within the `powerjob-server` component, specifically in versions 5.1.0, 5.1.1, and 5.1.2. An attacker can remotely exploit this vulnerability by manipulating the `customQuery` argument of the `detailPlus` endpoint, injecting malicious SQL code that is then executed by the application's database. This could lead to unauthorized data access, modification, or deletion. Despite being reported through an issue report, the project has not yet provided a patch or mitigation. This vulnerability poses a significant risk to organizations using vulnerable versions of PowerJob, potentially enabling attackers to compromise sensitive data and disrupt critical job scheduling processes.

## Attack Chain

1.  Attacker identifies a vulnerable PowerJob instance running versions 5.1.0, 5.1.1, or 5.1.2.
2.  Attacker crafts a malicious SQL injection payload, targeting the `customQuery` parameter of the `/detailPlus` endpoint.
3.  Attacker sends a crafted HTTP request to the vulnerable `/detailPlus` endpoint, embedding the SQL injection payload within the `customQuery` parameter.
4.  The PowerJob server receives the request and processes the `customQuery` parameter without proper sanitization or validation.
5.  The unsanitized `customQuery` value is incorporated into an SQL query executed against the PowerJob database.
6.  The injected SQL code is executed, allowing the attacker to bypass intended security restrictions and perform unauthorized database operations.
7.  The attacker may extract sensitive data, modify existing records, or even gain control over the underlying database server.
8.  Depending on the attacker's objectives, they may leverage the compromised database to pivot to other systems or disrupt critical job scheduling processes.

## Impact

Successful exploitation of CVE-2026-5736 can lead to a complete compromise of the PowerJob server and its associated database. An attacker could potentially gain access to sensitive data related to job schedules, configurations, and execution history. They could also modify existing jobs, create new malicious jobs, or even disrupt the entire job scheduling system. The exact impact depends on the scope of data stored in the PowerJob database and the attacker's objectives, but could include data theft, service disruption, and potentially lateral movement within the compromised network.

## Recommendation

*   Upgrade PowerJob to a patched version that addresses CVE-2026-5736 as soon as it becomes available from the vendor.
*   Implement input validation and sanitization on the `customQuery` parameter in the `detailPlus` endpoint to prevent SQL injection attacks.
*   Deploy the provided Sigma rule `Detect Suspicious PowerJob customQuery Parameter` to detect potential exploitation attempts targeting the vulnerable endpoint.
*   Monitor web server logs for suspicious requests to the `/detailPlus` endpoint containing potentially malicious SQL injection payloads, as covered in the logsource for the Sigma rule.
