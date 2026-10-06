---
title: SQL Injection in Kusalkasilva Learning-Management-System Login Endpoint
slug: 2026-10-kusalkasilva-sqli
description: A remote, unauthenticated SQL injection vulnerability in the login.php script of Kusalkasilva Learning-Management-System allows attackers to compromise database integrity.
date: "2026-10-06T12:55:11Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:kusalkasilva:learning-management-system:*:*:*:*:*:*:*:*
vendors:
  - Kusalkasilva
products:
  - Learning-Management-System
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The attack can be initiated remotely.
    confidence_band: high
cves:
  - id: CVE-2026-105918
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-105918
rules:
  - title: Detect CVE-2026-105918 Exploitation - SQL Injection in Login Endpoint
    description: Detects attempted SQL injection via the username or password parameter in the login.php endpoint.
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
    - action: Deploy WAF rules to sanitize username and password input
      owner: SOC
      due: 24h
      evidence: Source details SQL injection vulnerability in login.php
  hunt_leads:
    - lead: Search web logs for high frequency of login errors or unusual SQL characters in login requests
      technique_id: T1190
      data_needed:
        - webserver access logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Vulnerability allows remote SQL injection
  mitigation_plan:
    - priority: short_term
      action: Monitor project repository for software update to address the mysql_error function
      owner: IT Operations
      addresses: CVE-2026-105918
      evidence: No version details of affected nor updated releases are available
---

The Kusalkasilva Learning-Management-System is susceptible to a SQL injection vulnerability (CVE-2026-105918) within the mysql_error function located in the login.php file. This component handles the Login Endpoint for the application. Remote attackers can leverage this vulnerability by providing malicious input into the username or password parameters, enabling them to alter database queries. This flaw, which carries a CVSS v3.1 base score of 7.3, poses a significant risk as the exploit is publicly available. Because the project utilizes a continuous delivery model with rolling releases, no specific patched versions or version ranges are available; users should monitor the project repository for updates and maintain defense-in-depth controls around database access.

## Impact

Successful exploitation allows an unauthenticated remote attacker to execute arbitrary SQL commands against the backend database. This may lead to unauthorized data exfiltration, modification of application records, or complete compromise of the learning management system's data integrity.

## Recommendation

- Implement web application firewall (WAF) rules to inspect and filter SQL injection payloads in the username and password parameters of login.php.
- Apply the principle of least privilege to the database service account used by the Learning-Management-System to limit the potential impact of successful query manipulation.
- Monitor logs for unusual database error patterns or unexpected login attempts that deviate from standard user activity.
- Monitor the Kusalkasilva Learning-Management-System source repository for commit notifications indicating a security fix for the mysql_error function.
