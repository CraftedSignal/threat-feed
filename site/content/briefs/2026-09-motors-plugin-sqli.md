---
title: 'CVE-2026-6806: Unauthenticated SQL Injection in The Motors WordPress Plugin'
slug: 2026-09-motors-plugin-sqli
description: The Motors - Car Dealership & Classified Listings WordPress plugin is vulnerable to unauthenticated time-based blind SQL injection in versions up to 1.4.109, allowing remote attackers to extract sensitive database information.
date: "2026-09-30T08:33:17Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:stylemixthemes:the_motors:*:*:*:*:*:wordpress:*:*
tags:
  - web-application
  - sql-injection
  - wordpress
  - cve-2026-6806
vendors:
  - WordPress
products:
  - The Motors – Car Dealership & Classified Listings Plugin (<= 1.4.109)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The Motors – Car Dealership & Classified Listings Plugin plugin for WordPress is vulnerable to time-based blind SQL Injection via the 'stm_lat/stm_lng' parameter
    confidence_band: high
cves:
  - id: CVE-2026-6806
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6806
rules:
  - title: Detects CVE-2026-6806 Exploitation - SQL Injection in The Motors Plugin
    description: Detects attempts to exploit time-based blind SQL injection via stm_lat or stm_lng parameters in The Motors WordPress plugin
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
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade The Motors plugin to the latest version post-1.4.109
      owner: IT Operations
      due: 24h
      evidence: Source states plugin is vulnerable in versions <= 1.4.109
  mitigation_plan:
    - priority: immediate
      action: Deploy WAF rules to filter SQL keywords in plugin parameters
      owner: SOC
      addresses: CVE-2026-6806
      evidence: Source identifies SQL injection as the vulnerability type
---

The Motors - Car Dealership & Classified Listings plugin for WordPress contains a critical SQL injection vulnerability identified as CVE-2026-6806. The flaw exists in all versions up to and including 1.4.109. It stems from improper input sanitization and a lack of parameterized queries when processing the 'stm_lat' and 'stm_lng' parameters. An unauthenticated remote attacker can exploit this vulnerability by injecting malicious SQL payloads into these parameters, triggering time-based blind SQL injection. By observing the server response time variations, attackers can infer database content, potentially leading to unauthorized data extraction, including sensitive user information or administrative credentials stored within the WordPress database. Given that the plugin is used for classified listings, the impact to site confidentiality is significant.

## Impact

Successful exploitation allows unauthenticated attackers to read arbitrary data from the WordPress database. This can lead to the compromise of user accounts, configuration settings, and private business data managed by the plugin. Organizations running affected versions are at high risk of data exfiltration.

## Recommendation

* Update the 'The Motors - Car Dealership & Classified Listings Plugin' to the latest version available beyond 1.4.109 to include the necessary input escaping and query preparation.
* Monitor web application firewall (WAF) logs for abnormal HTTP POST or GET requests targeting plugin endpoints that contain SQL metacharacters (e.g., SLEEP, WAITFOR, BENCHMARK) within the 'stm_lat' or 'stm_lng' parameters.
* Restrict public access to non-essential administrative or listing-submission endpoints where possible until patching is completed.
