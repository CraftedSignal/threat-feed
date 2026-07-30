---
title: Blind SQL Injection Vulnerability in Plesk XML-RPC API
slug: 2026-07-plesk-sql-injection
description: A blind SQL injection vulnerability, tracked as CVE-2026-58046, affects the Plesk XML-RPC API, potentially allowing unauthenticated attackers to execute arbitrary database queries.
date: "2026-07-30T15:30:41Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - web-application
  - sql-injection
  - vulnerability
vendors:
  - WebPros
products:
  - Plesk
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A blind SQL injection vulnerability exists in the XML-RPC API of Plesk.
    confidence_band: high
cves:
  - id: CVE-2026-58046
    cvss: 9.9
    epss: 0.00306
references:
  - https://cyber.gc.ca/en/alerts-advisories/webpros-security-advisory-av26-761
  - https://support.plesk.com/hc/en-us/articles/42139500580119-Vulnerability-CVE-2026-58046-Blind-SQL-injection-in-Plesk-s-XML-RPC-API
rules:
  - title: Detects CVE-2026-58046 Exploitation - SQL Injection in Plesk XML-RPC API
    description: Detects potential blind SQL injection attempts by searching for common SQL keywords and character sequences in POST requests to the XML-RPC API endpoint.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
---

WebPros has issued a security advisory regarding a high-severity blind SQL injection vulnerability affecting the Plesk control panel, specifically within its XML-RPC API. The vulnerability, identified as CVE-2026-58046, impacts all Plesk versions prior to 18.0.79.4. This flaw permits an unauthenticated attacker to inject malicious SQL commands into the API, potentially leading to unauthorized data access, database modification, or sensitive information disclosure from the Plesk backend. Administrators are urged to update to version 18.0.79.4 or later to mitigate this risk. Because the vulnerability lies within the API interface, it is reachable over the network and does not require local system access or elevated user privileges, making it a priority for immediate patching in internet-facing deployments.

## Impact

Successful exploitation of CVE-2026-58046 allows an unauthenticated remote attacker to execute arbitrary SQL queries against the Plesk database. This could lead to full unauthorized access to site configurations, user credentials, database contents, and other administrative data managed by Plesk. Such access could result in comprehensive data exfiltration or total compromise of hosted services. Organizations running legacy versions of Plesk are at risk if their API endpoints are accessible to untrusted networks.

## Recommendation

* Update all Plesk instances to version 18.0.79.4 or newer immediately to remediate CVE-2026-58046.
* Review web server access logs for anomalous POST requests directed at XML-RPC API endpoints, specifically looking for common SQL injection characters (such as single quotes, semicolons, or sleep commands) in API payloads.
* Restrict network access to the Plesk administrative interface and API endpoints to trusted IP addresses using firewall rules or ACLs to minimize the attack surface until patching is complete.
