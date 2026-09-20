---
title: SQL Injection Vulnerability in Internship Management System
slug: 2026-09-internship-management-system-sqli
description: Internship Management System version 1.0 is vulnerable to unauthenticated remote SQL injection via the Password parameter in login.php, for which public exploit code is available.
date: "2026-09-20T12:20:43Z"
lastmod: "2026-09-20T12:20:54Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:code-projects:internship_management_system:1.0:*:*:*:*:*:*:*
tags:
  - cve-2026-93979
  - sql-injection
  - web-vulnerability
vendors:
  - code-projects
products:
  - Internship Management System (1.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Such manipulation of the argument Password leads to sql injection.
    confidence_band: high
cves:
  - id: CVE-2026-93978
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-93978
  - https://nvd.nist.gov/vuln/detail/CVE-2026-93979
rules:
  - title: Detects CVE-2026-93978 Exploitation - SQL Injection in login.php
    description: Detects attempted SQL injection via the Password parameter in login.php, characteristic of CVE-2026-93978 exploitation
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
    - action: Inventory all servers running Internship Management System 1.0
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-93978 vulnerability report
    - action: Deploy WAF rules to block malicious SQL patterns targeting /login.php
      owner: SOC
      due: 48h
      evidence: CVE-2026-93978 public exploit availability
  hunt_leads:
    - lead: Search logs for unusual character sequences in POST requests to /login.php
      technique_id: T1190
      data_needed:
        - Web server access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source states SQL injection via Password parameter in login.php
updates:
  - at: "2026-09-20T12:20:54Z"
    level: L2
    summary: added coverage for Internship Management System (1.0)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-93979
---

Internship Management System version 1.0 contains a critical SQL injection vulnerability identified as CVE-2026-93978. The flaw exists within the login.php file and specifically affects the 'Password' input parameter. An unauthenticated remote attacker can inject arbitrary SQL commands into the application database by manipulating this field during the authentication process. Because the exploit is publicly available, the risk of automated or manual exploitation by threat actors is elevated. This vulnerability is significant as it potentially allows for bypass of authentication mechanisms, unauthorized data extraction, or administrative access to the underlying database environment. Organizations running this specific version of the Internship Management System are encouraged to restrict network access to the application login interface until a patch or mitigation is applied by the maintainers.

## Impact

Successful exploitation of this vulnerability allows unauthenticated attackers to execute arbitrary SQL queries against the backend database, leading to potential loss of confidentiality, integrity, and availability. This includes unauthorized access to administrative accounts, extraction of sensitive student or management information, and potential modification of application data.

## Recommendation

Prioritize the identification and isolation of all instances of the Internship Management System 1.0 within the environment. Deploy web application firewall (WAF) rules designed to detect and block SQL injection patterns targeting the 'Password' parameter in 'login.php'. Monitor web server access logs for anomalous characters (such as single quotes, semicolons, or comment indicators) directed at the authentication endpoint. Given that the exploit is publicly available, treat any attempts to access 'login.php' with unusual input strings as an indicator of attempted exploitation.
