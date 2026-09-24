---
title: SQL Injection in pmTicket Project-Management-Software
slug: 2026-09-pmticket-sql-injection
description: An unauthenticated remote SQL injection vulnerability in pmTicket Project-Management-Software allows attackers to execute arbitrary SQL commands via the 'conn_settings' parameter in /ajax/add_project.php.
date: "2026-09-24T00:45:37Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:pmticket:project_management_software:*:*:*:*:*:*:*:*
tags:
  - web-vulnerability
  - sqli
  - vulnerability
vendors:
  - pmTicket
products:
  - Project-Management-Software (up to commit 078fa56a782490c5059a0814f84df27984f4d7e2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The attack may be launched remotely.
    confidence_band: high
cves:
  - id: CVE-2026-96751
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-96751
rules:
  - title: Detects CVE-2026-96751 Exploitation - SQL Injection in pmTicket
    description: Detects exploitation attempts against CVE-2026-96751 by monitoring for suspicious SQL injection patterns in the conn_settings parameter sent to the add_project.php script.
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
    - action: Deploy WAF rule to block common SQL injection patterns targeting /ajax/add_project.php
      owner: SOC
      due: 24h
      evidence: CVE-2026-96751 advisory
  mitigation_plan:
    - priority: immediate
      action: Verify installation version against repository commit hash 078fa56a782490c5059a0814f84df27984f4d7e2
      owner: IT Operations
      addresses: CVE-2026-96751
      evidence: NVD vulnerability disclosure
---

A SQL injection vulnerability exists in the pmTicket Project-Management-Software, specifically affecting the 'setSync' function within the '/ajax/add_project.php' file. The vulnerability arises from improper sanitization of the 'conn_settings' input argument, allowing remote, unauthenticated attackers to inject and execute arbitrary SQL commands. This flaw affects all versions of the software up to commit hash 078fa56a782490c5059a0814f84df27984f4d7e2. As the software follows a rolling release model, there are no specific version numbers to track; users are advised to verify their current build against the latest available repository state. The vendor has remained unresponsive to disclosure attempts, necessitating proactive defensive measures by administrators hosting this application.

## Impact

Successful exploitation of this vulnerability allows an unauthenticated remote attacker to gain unauthorized access to the underlying database. This can lead to the exfiltration of project-related sensitive data, manipulation of internal application state, or potential full administrative control over the application backend, depending on database permissions.

## Recommendation

1. Deploy a Web Application Firewall (WAF) or equivalent monitoring solution to inspect and block HTTP requests to /ajax/add_project.php containing SQL injection payloads in the 'conn_settings' parameter.
2. Implement strict input validation and parameterization for all SQL queries within the application codebase.
3. Conduct an audit of the current application build against the latest commit hash in the upstream repository to ensure the patch is applied.
4. Ensure the database user account utilized by the pmTicket application is restricted to the minimum necessary privileges (Principle of Least Privilege) to minimize the impact of potential SQL injection exploitation.
