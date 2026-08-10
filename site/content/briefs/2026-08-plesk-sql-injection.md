---
title: Blind SQL Injection Vulnerability in Plesk Obsidian
slug: 2026-08-plesk-sql-injection
description: Plesk Obsidian versions prior to 18.0.80.1 and 18.0.79.5 are vulnerable to a blind SQL injection (CVE-2026-64636) which allows unauthenticated or low-privileged attackers to execute unauthorized database queries.
date: "2026-08-10T19:30:39Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - sql-injection
  - web-application
vendors:
  - WebPros
products:
  - Plesk Obsidian
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The vulnerability allows an unauthenticated or low-privileged attacker to perform unauthorized database operations by injecting malicious SQL queries.
    confidence_band: high
cves:
  - id: CVE-2026-64636
    cvss: 7.7
    epss: 0.00215
references:
  - https://cyber.gc.ca/en/alerts-advisories/webpros-security-advisory-av26-790
  - https://support.plesk.com/hc/en-us/articles/42431868205079-CVE-2026-64636-Vulnerability-in-Plesk-blind-SQL-injection
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch Plesk Obsidian to 18.0.80.1 or 18.0.79.5 to address CVE-2026-64636
      owner: IT Operations
      due: 24h
      evidence: Vendor security advisory AV26-790
  mitigation_plan:
    - priority: immediate
      action: Restrict external network access to the Plesk management interface
      owner: IT Operations
      addresses: CVE-2026-64636
      evidence: Blind SQL injection vulnerability
---

WebPros has released a security advisory regarding a critical blind SQL injection vulnerability, tracked as CVE-2026-64636, affecting Plesk Obsidian. This vulnerability exists in versions prior to 18.0.80.1 and 18.0.79.5. The flaw enables an attacker to manipulate backend database queries, potentially leading to unauthorized data exposure, modification, or administrative account compromise. Given the prevalence of Plesk in web hosting environments, this vulnerability presents a significant risk to hosted websites and server management configurations. Security teams should prioritize patching Plesk installations to the latest versions to mitigate the risk of remote database exploitation.

## Impact

Successful exploitation of CVE-2026-64636 allows an attacker to interact with the underlying database of the Plesk management interface. This can lead to the exfiltration of sensitive configuration data, user credentials, or the ability to modify web application settings. The scope includes all server environments running outdated versions of Plesk Obsidian that are exposed to the internet.

## Recommendation

- Upgrade all Plesk Obsidian instances to version 18.0.80.1, 18.0.79.5, or later immediately.
- Review web server access logs for anomalous requests containing SQL syntax (e.g., SELECT, UNION, SLEEP) targeting the Plesk management interface endpoints.
- Restrict access to the Plesk admin panel by IP address or VPN to minimize the attack surface until patches are applied.
