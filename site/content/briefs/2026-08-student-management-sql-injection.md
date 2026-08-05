---
title: SQL Injection Vulnerability in Student-Management-System
slug: 2026-08-student-management-sql-injection
description: An unauthenticated remote SQL injection vulnerability in the Student-Management-System Login component allows attackers to execute arbitrary database commands via the loginCheckTest.php endpoint.
date: "2026-08-05T21:20:39Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - imranrisal-dev
products:
  - Student-Management-System
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The manipulation of the argument username/password results in sql injection.
    confidence_band: high
cves:
  - id: CVE-2026-18958
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-18958
rules:
  - title: Detects CVE-2026-18958 Exploitation - SQL Injection in loginCheckTest.php
    description: Detects POST requests to loginCheckTest.php containing common SQL injection characters in the username or password parameters.
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
    - IT Operations
  immediate_actions:
    - action: Review perimeter logs for access to /loginCheckTest.php
      owner: SOC
      due: 24h
      evidence: CVE-2026-18958 public exploit availability
  mitigation_plan:
    - priority: immediate
      action: Deploy WAF rules to block SQL injection characters in login parameters
      owner: IT Operations
      addresses: CVE-2026-18958
      evidence: NVD vulnerability description
---

A critical SQL injection vulnerability, tracked as CVE-2026-18958, has been identified in the Student-Management-System component maintained by imranrisal-dev. The flaw exists within the loginCheckTest.php file, which processes login requests for the application. Due to insufficient input sanitization of the username and password parameters, an unauthenticated remote attacker can inject arbitrary SQL commands into the backend database. This vulnerability allows for unauthorized data access, modification of existing records, or potential bypass of authentication mechanisms. The vendor has not responded to disclosure attempts, and proof-of-concept exploit code is currently public, significantly increasing the risk of exploitation.

## Impact

Successful exploitation of this vulnerability permits remote attackers to perform unauthorized database queries. This can lead to full compromise of the application data, including sensitive student information, administrator credentials, or configuration data. Given the lack of vendor response and the public availability of exploits, all instances of this software are at high risk of automated or targeted exploitation attempts.

## Recommendation

- Perform an inventory of all instances of the Student-Management-System within the environment.
- Implement strict input validation or Web Application Firewall (WAF) rules to inspect and filter POST requests to loginCheckTest.php for SQL syntax characters.
- Evaluate the necessity of hosting this software; if it is not business-critical, disconnect it from the network until a patch or mitigation is verified.
- Monitor web server logs for suspicious activity targeting the loginCheckTest.php endpoint.
