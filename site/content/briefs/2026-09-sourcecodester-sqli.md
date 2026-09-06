---
title: SQL Injection in SourceCodester Online Voting System
slug: 2026-09-sourcecodester-sqli
description: SourceCodester Online Voting System 1.0 is vulnerable to remote SQL injection via the 'id' parameter in the '/ajax.php?action=save_user' endpoint, enabling unauthenticated attackers to manipulate database queries.
date: "2026-09-06T03:35:58Z"
lastmod: "2026-09-06T03:36:10Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:sourcecodester:online_voting_system:1.0:*:*:*:*:*:*:*
tags:
  - sqli
  - web-vulnerability
vendors:
  - SourceCodester
products:
  - Online Voting System (1.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This manipulation of the argument ID causes sql injection.
    confidence_band: high
cves:
  - id: CVE-2026-86159
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-86159
  - https://nvd.nist.gov/vuln/detail/CVE-2026-86161
rules:
  - title: Detects CVE-2026-86159 Exploitation - SQL Injection via ajax.php
    description: Detects exploitation attempts against SourceCodester Online Voting System by looking for SQL injection metacharacters within the id parameter of the save_user action.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detects CVE-2026-86161 Exploitation - SQL Injection in ajax.php
    description: Detects potential SQL injection attempts targeting the Online Voting System ajax.php endpoint by looking for common SQL injection payloads in the 'id' parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Monitor web logs for suspicious activity targeting /ajax.php
      owner: SOC
      due: 24h
      evidence: Exploit has been published and may be used.
  mitigation_plan:
    - priority: immediate
      action: Restrict access to /ajax.php via WAF rules or IP whitelisting
      owner: IT Operations
      addresses: CVE-2026-86159
      evidence: Vulnerability allows remote SQL injection
updates:
  - at: "2026-09-06T03:36:10Z"
    level: L2
    summary: 'added detection rule: Detects CVE-2026-86161 Exploitation - SQL Injection in ajax.php'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-86161
---

SourceCodester Online Voting System version 1.0 contains a SQL injection vulnerability within the /ajax.php endpoint. The flaw is specifically triggered through the 'id' parameter when the action is set to 'save_user'. An unauthenticated remote attacker can inject arbitrary SQL commands into the application's database queries. This vulnerability is significant because the exploit code has been publicly released, increasing the likelihood of exploitation. Successful exploitation allows an attacker to bypass authentication, extract sensitive voter information, modify database records, or potentially gain further control over the underlying web application environment. Defenders should prioritize auditing web server access logs for requests to the /ajax.php endpoint containing SQL metacharacters.

## Impact

Successful exploitation of CVE-2026-86159 allows an attacker to gain unauthorized access to the backend database, potentially leading to the theft of personal voter data, integrity loss of voting records, or total compromise of the application data layer.

## Recommendation

1. Deploy a Web Application Firewall (WAF) rule to block requests to '/ajax.php' that contain SQL injection patterns (e.g., UNION, SELECT, OR 1=1) within the 'id' parameter.
2. Audit web server access logs (Apache, Nginx, or IIS) for POST requests to '/ajax.php' where the query string or body contains the 'action=save_user' and 'id' parameters, and inspect these for potential SQL injection strings.
3. Ensure that the web application implements parameterized queries (prepared statements) to neutralize the SQL injection vector, as SourceCodester has not provided a patch for this version.
