---
title: SQL Injection Vulnerability in Abdurrab5 online-makeup-store
slug: 2026-09-sql-injection-online-makeup-store
description: An unauthenticated SQL injection vulnerability in the Admin Login Handler of Abdurrab5 online-makeup-store allows remote attackers to manipulate authentication parameters via index.php.
date: "2026-09-23T22:46:34Z"
lastmod: "2026-09-23T22:46:42Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:abdurrab5:online_makeup_store:*:*:*:*:*:*:*:*
tags:
  - web-application
  - sql-injection
  - cve-2026-96601
  - vulnerability
vendors:
  - Abdurrab5
products:
  - online-makeup-store
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The manipulation of the argument id/password results in sql injection.
    confidence_band: high
cves:
  - id: CVE-2026-96601
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-96601
  - https://nvd.nist.gov/vuln/detail/CVE-2026-96602
rules:
  - title: Detects CVE-2026-96601 Exploitation - SQL Injection in Admin Login
    description: Detects HTTP POST or GET requests to index.php containing common SQL injection patterns in the id or password parameters
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detects CVE-2026-96602 Exploitation - SQL Injection in customerSignin.php
    description: Detects attempts to exploit SQL injection in the customerSignin.php script via the username or password parameters.
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
    - action: Deploy WAF rules blocking common SQLi patterns directed at /index.php
      owner: SOC
      due: 24h
      evidence: CVE-2026-96601 public exploit availability
  mitigation_plan:
    - priority: immediate
      action: Implement parameterized database queries in index.php
      owner: IT Operations
      addresses: CVE-2026-96601
      evidence: NVD vulnerability details
updates:
  - at: "2026-09-23T22:46:42Z"
    level: L2
    summary: 'added detection rule: Detects CVE-2026-96602 Exploitation - SQL Injection in customerSignin.php'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-96602
---

A SQL injection vulnerability, tracked as CVE-2026-96601, has been identified in the Abdurrab5 online-makeup-store web application. The vulnerability resides within the Admin Login Handler component, specifically affecting the processing of input passed to the index.php script. An unauthenticated remote attacker can inject malicious SQL commands into the 'id' or 'password' arguments to bypass authentication or extract sensitive data from the backend database. As the application utilizes a rolling release model, there is no specific version identifier to patch against; users are advised to verify their implementation against the vulnerable file path. Public exploits for this vulnerability are currently available, increasing the risk of opportunistic exploitation.

## Impact

Successful exploitation of CVE-2026-96601 allows unauthorized access to administrative functions of the online-makeup-store. An attacker could potentially retrieve, modify, or delete database contents, leading to account takeover or full compromise of the application's backend data.

## Recommendation

Detection engineering teams should focus on monitoring web server access logs for anomalous patterns indicative of SQL injection attempts targeting the Admin Login Handler.

- Implement input validation and parameterized queries for the 'id' and 'password' parameters in index.php.
- Deploy web application firewall (WAF) rules to inspect POST and GET requests to index.php for common SQL injection syntax (e.g., OR 1=1, UNION SELECT, --).
- Review web server logs for high-frequency or anomalous status codes (4xx/5xx) associated with the /index.php path from external IP addresses.
