---
title: SQL Injection in SourceCodester Online Reviewer System
slug: 2026-10-online-reviewer-sql-injection
description: A remote SQL injection vulnerability in SourceCodester Online Reviewer System 1.0 allows attackers to execute arbitrary SQL commands via the login endpoint.
date: "2026-10-13T18:37:04Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:sourcecodester:online_reviewer_system:1.0:*:*:*:*:*:*:*
tags:
  - web-vulnerability
  - sql-injection
  - remote-execution
vendors:
  - SourceCodester
products:
  - Online Reviewer System (1.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The Online Reviewer System 1.0 contains a SQL injection vulnerability in the login/index.php file, specifically within the PDO::prepare function.
    confidence_band: high
cves:
  - id: CVE-2026-109620
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-109620
rules:
  - title: Detect CVE-2026-109620 Exploitation - SQL Injection in login/index.php
    description: Detects HTTP POST requests to login/index.php containing SQL injection characters in common parameters.
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
    - action: Restrict external access to the Online Reviewer System login page
      owner: IT Operations
      due: 24h
      evidence: Public disclosure and available exploit code
  hunt_leads:
    - lead: Search web logs for 200/500 status codes on /login/index.php associated with SQL syntax characters
      technique_id: T1190
      data_needed:
        - webserver access logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Vulnerability allows remote SQL injection
  mitigation_plan:
    - priority: immediate
      action: Disable the affected application until a vendor patch is issued
      owner: IT Operations
      addresses: CVE-2026-109620
      evidence: SourceCodester Online Reviewer System 1.0 identified as vulnerable
---

SourceCodester Online Reviewer System 1.0 is vulnerable to SQL injection (CVE-2026-109620) within the login/index.php file. The vulnerability originates from improper neutralization of special elements used in an SQL command within the PDO::prepare function. An unauthenticated remote attacker can supply malicious input via the username or password fields to manipulate the backend SQL query execution. This vulnerability has been publicly disclosed, and exploit code is available, increasing the risk of unauthorized database access, credential harvesting, or administrative account takeover for organizations hosting this application.

## Impact

Successful exploitation allows remote attackers to bypass authentication or extract sensitive data stored within the backend database. This impact is critical for any environment where this system is exposed to the internet. As this is a publicly disclosed vulnerability with exploit code available, organizations should assume that opportunistic scanning and exploitation may occur.

## Recommendation

* Immediately restrict public access to the Online Reviewer System login page while evaluating the impact.
* Audit web server logs for suspicious POST requests to login/index.php containing SQL metacharacters (e.g., single quotes, comment delimiters).
* Check for anomalous database query patterns consistent with automated SQL injection tools (e.g., sqlmap).
* Given the lack of a vendor patch for this version, consider migrating to a more secure authentication mechanism or disabling the application until an official security update is provided by SourceCodester.
