---
title: SQL Injection in DataLife Engine Search Module
slug: 2026-09-datalife-sql-injection
description: DataLife Engine 18.0 contains a remote SQL injection vulnerability in the search module's strip_data function, allowing unauthorized database queries via the story argument.
date: "2026-09-23T22:46:52Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:dle-news:datalife_engine:18.0:*:*:*:*:*:*:*
tags:
  - web-vulnerability
  - sql-injection
  - cve-2026-96604
vendors:
  - SoftNews Media Group
products:
  - DataLife Engine (18.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The manipulation of the argument story leads to sql injection.
    confidence_band: high
cves:
  - id: CVE-2026-96604
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-96604
rules:
  - title: Detects CVE-2026-96604 Exploitation - SQL Injection in DataLife Engine
    description: Detects potential SQL injection attempts targeting the DataLife Engine search module by identifying common SQL keywords and special characters within the story parameter.
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
    - action: Review WAF logs for incoming requests matching the rule signature
      owner: SOC
      due: 24h
      evidence: Source confirms public availability of exploit material
  mitigation_plan:
    - priority: immediate
      action: Implement WAF filtering to block requests containing SQL metacharacters in the story parameter
      owner: IT Operations
      addresses: CVE-2026-96604
      evidence: Public exploit available for this SQL injection flaw
---

SoftNews Media Group DataLife Engine version 18.0 contains a high-severity SQL injection vulnerability identified as CVE-2026-96604. The flaw exists within the strip_data function located in engine/modules/search.php. An unauthenticated remote attacker can exploit this by injecting malicious SQL commands into the story argument processed by the search module. This vulnerability allows for unauthorized interaction with the underlying database, potentially leading to data exfiltration or administrative compromise of the web application. Publicly available exploit material increases the risk of opportunistic targeting. The vendor has not responded to disclosure efforts, leaving installations currently exposed without an official security patch.

## Impact

Successful exploitation allows remote attackers to execute arbitrary SQL queries against the DataLife Engine database. This can result in the full disclosure of sensitive user data, credential theft, or unauthorized modification of web content. Given the public availability of exploit code, organizations running DataLife Engine 18.0 are at immediate risk of automated scanning and exploitation by threat actors.

## Recommendation

* Monitor web server logs for suspicious requests to engine/modules/search.php containing SQL syntax characters (e.g., UNION, SELECT, OR, --, ') within the story parameter.
* Implement Web Application Firewall (WAF) rules to inspect and sanitize input directed at the search module's story argument.
* Audit access to the database layer to identify any unexpected query patterns originating from the web application's search functionality.
* Because the vendor has not provided a patch, consider implementing temporary input validation or sanitization patches at the application level to strip SQL metacharacters from the story parameter before processing.
