---
title: SQL Injection Vulnerability in Raisecom Communication Command and Dispatch Management Platform
slug: 2026-08-raisecom-sql-injection
description: An unauthenticated remote SQL injection vulnerability in the Raisecom Communication Command and Dispatch Management Platform allows attackers to execute arbitrary database queries via the 'sip' parameter in 'getpwd.php'.
date: "2026-08-14T02:06:15Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Raisecom
products:
  - Communication Command and Dispatch Management Platform (7.6.5)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The attack can be executed remotely.
    confidence_band: high
cves:
  - id: CVE-2026-19764
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-19764
  - https://vuldb.com/vuln/389667
rules:
  - title: Detects CVE-2026-19764 Exploitation - SQL Injection in getpwd.php
    description: Detects exploitation attempts against the Raisecom platform by monitoring for SQL injection syntax in requests to the vulnerable getpwd.php script.
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
    - action: Deploy WAF filters to block identified SQL injection patterns targeting getpwd.php
      owner: SOC
      due: 24h
      evidence: Exploit is publicly available and remote execution is possible.
  mitigation_plan:
    - priority: immediate
      action: Restrict access to the /app/users/ directory to trusted administrative network segments
      owner: IT Operations
      addresses: CVE-2026-19764
      evidence: Vulnerability allows remote, unauthenticated access.
---

A critical SQL injection vulnerability has been identified in the Raisecom Communication Command and Dispatch Management Platform, specifically impacting versions up to and including 7.6.5. The vulnerability resides within the '/app/users/getpwd.php' script, where the 'sip' parameter is improperly neutralized before being processed by the backend database. This flaw allows remote, unauthenticated attackers to manipulate SQL queries, potentially leading to unauthorized data exfiltration, database modification, or administrative account compromise. Publicly available exploit code for this vulnerability has been reported, increasing the risk of exploitation. Defenders should treat this as a high-priority risk due to the potential for unauthenticated remote code execution and the current lack of vendor-provided patches.

## Attack Chain

1. Attacker performs reconnaissance to identify internet-facing instances of Raisecom Communication Command and Dispatch Management Platform.
2. Attacker crafts a malicious HTTP GET or POST request targeting '/app/users/getpwd.php'.
3. Attacker injects crafted SQL payloads into the 'sip' parameter of the identified script.
4. The web application's backend database engine processes the malicious input without proper sanitization.
5. The injection allows the attacker to bypass authentication or extract sensitive data from the database.
6. Attacker may escalate privileges by dumping credentials or modifying administrative user tables within the database.
7. Attacker achieves persistent access or objective-based impact through unauthorized database control.

## Impact

Successful exploitation of this vulnerability allows unauthenticated attackers to gain unauthorized access to the underlying database of the Raisecom platform. This can result in complete data exposure, integrity loss of system records, and potential system-wide compromise. Given the platform's role in command and dispatch operations, compromise could lead to operational disruption and the loss of sensitive communication logs or user credentials.

## Recommendation

- Implement strict input validation and sanitization for the 'sip' parameter in all web-facing components of the Raisecom platform.
- Deploy WAF rules to block incoming HTTP requests to '/app/users/getpwd.php' that contain common SQL injection syntax (e.g., 'UNION', 'SELECT', 'OR 1=1', '--').
- Restrict access to the '/app/users/' directory at the web server level to trusted management IPs only.
- Monitor web server logs for suspicious requests to 'getpwd.php' containing abnormal characters or SQL keywords in query parameters.
- Audit database access logs for queries originating from the application service account that display unauthorized table selection or credential dumping behavior.
