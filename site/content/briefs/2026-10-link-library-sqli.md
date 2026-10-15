---
title: 'CVE-2026-15090: SQL Injection in Link Library WordPress Plugin'
slug: 2026-10-link-library-sqli
description: The Link Library plugin for WordPress is vulnerable to unauthenticated time-based SQL injection via the 'link_url' parameter, enabling potential database information exfiltration.
date: "2026-10-15T06:35:33Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:link_library_project:link_library:*:*:*:*:*:wordpress:*:*
tags:
  - web-application-vulnerability
  - sql-injection
  - wordpress
vendors:
  - WordPress
products:
  - Link Library (<= 7.9.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Unauthenticated attackers can exploit insufficient input sanitization to execute arbitrary SQL queries.
    confidence_band: high
cves:
  - id: CVE-2026-15090
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-15090
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Link Library plugin to version > 7.9.2
      owner: IT Operations
      due: 24h
      evidence: Source identifies vulnerability in versions <= 7.9.2
  mitigation_plan:
    - priority: immediate
      action: Patch plugin to version 7.9.3 or higher
      owner: IT Operations
      addresses: CVE-2026-15090
      evidence: Plugin version 7.9.2 is explicitly identified as vulnerable.
---

The Link Library plugin for WordPress (versions 7.9.2 and earlier) contains a critical security flaw identified as CVE-2026-15090. This vulnerability is a time-based SQL injection resulting from insufficient sanitization of the 'link_url' parameter and the failure to use prepared statements in the underlying SQL queries. An unauthenticated attacker can exploit this flaw by sending crafted HTTP requests containing malicious SQL payloads. By observing time delays in the server response, attackers can iteratively infer data from the database. This vulnerability poses a significant risk to the confidentiality of site data, as successful exploitation allows for unauthorized extraction of sensitive information from the WordPress database. Defenders should note that this vulnerability is exploitable via standard web traffic targeting the plugin's interface.

## Impact

Successful exploitation of this vulnerability allows unauthenticated attackers to perform blind SQL injection against the WordPress database. This can lead to the full compromise of sensitive data, including user credentials, configuration details, and site content. Given the widespread use of WordPress plugins, organizations running versions 7.9.2 or earlier of Link Library are at high risk of data exfiltration.

## Recommendation

* Update the Link Library plugin to the latest available version beyond 7.9.2 immediately to patch the vulnerable parameter handling.
* Monitor web server access logs for anomalous POST or GET requests to the Link Library plugin endpoints containing common SQL injection characters (e.g., SLEEP, BENCHMARK, WAITFOR, or stacked query delimiters like ';').
* Implement a Web Application Firewall (WAF) to block requests containing suspected SQL injection patterns targeting the 'link_url' parameter.
