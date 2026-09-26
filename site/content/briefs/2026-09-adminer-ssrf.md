---
title: Unauthenticated Server-Side Request Forgery in Adminer ClickHouse Driver
slug: 2026-09-adminer-ssrf
description: Adminer versions 6.0.0 through 6.0.1 are vulnerable to a pre-authentication SSRF in the ClickHouse driver, allowing unauthenticated attackers to probe internal networks and exfiltrate sensitive response data.
date: "2026-09-26T15:12:52Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:adminer:adminer:6.0.0:*:*:*:*:*:*:*
  - cpe:2.3:a:adminer:adminer:6.0.1:*:*:*:*:*:*:*
tags:
  - web-application
  - ssrf
  - vulnerability
vendors:
  - Adminer
products:
  - Adminer (6.0.0-6.0.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated attacker can submit auth[driver]=clickhouse with auth[server] set to an arbitrary URL.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1595.002
    technique_name: 'Active Scanning: Vulnerability Scanning'
    evidence: This enables internal network/port reconnaissance and disclosure of sensitive information contained in internal error pages.
    confidence_band: high
cves:
  - id: CVE-2026-100697
    cvss: 8.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-100697
rules:
  - title: Detect CVE-2026-100697 Exploitation - Adminer ClickHouse SSRF
    description: Detects exploitation attempts targeting the Adminer ClickHouse driver SSRF vulnerability by monitoring for POST requests containing auth[driver] set to clickhouse and external or internal-range targets in the server parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1595.002
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Patch Adminer to 6.0.2 on all identified instances
      owner: IT Operations
      due: 24h
      evidence: Fixed in Adminer 6.0.2.
  hunt_leads:
    - lead: Search logs for unusual 'auth[server]' parameters in Adminer POST requests
      technique_id: T1190
      data_needed:
        - Web access logs with query string capture
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The SSRF vector relies on the auth[server] parameter.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Adminer instances to 6.0.2
      owner: IT Operations
      addresses: CVE-2026-100697
      evidence: Fixed in Adminer 6.0.2.
---

Adminer versions 6.0.0 through 6.0.1 contain a critical pre-authentication Server-Side Request Forgery (SSRF) vulnerability when the ClickHouse driver plugin (plugins/drivers/clickhouse.php) is active. The vulnerability stems from improper validation of the 'auth[server]' parameter during the login process. An unauthenticated attacker can submit a crafted HTTP request with 'auth[driver]=clickhouse' and a custom 'auth[server]' URL, forcing the Adminer server to issue an HTTP POST request containing 'SELECT version()' to the target host. 

When the destination service returns an error status (outside the 200-299 range, excluding 401/403), the Adminer application captures the raw response body and renders it directly on the login page. This behavior allows attackers to perform internal network reconnaissance, scan for open ports, and exfiltrate sensitive information, including internal hostnames, configuration details, and stack traces found in error messages. The vulnerability was addressed in Adminer 6.0.2.

## Impact

Successful exploitation allows unauthenticated attackers to map internal network infrastructure and disclose potentially sensitive metadata or configuration information from internal services unreachable from the public internet. This exposure can lead to further exploitation of internal-only systems, lateral movement, or the acquisition of credentials and configuration identifiers.

## Recommendation

* Upgrade Adminer to version 6.0.2 or later immediately to patch CVE-2026-100697.
* For environments where upgrading is delayed, use a Web Application Firewall (WAF) to block requests containing 'auth[driver]=clickhouse' where the 'auth[server]' parameter targets internal RFC1918 address spaces.
* Monitor web server logs for high volumes of POST requests to Adminer login pages containing unexpected values in the 'auth[server]' or 'auth[driver]' fields.
* Audit access logs for requests to the Adminer login endpoint that result in 200 OK responses containing error bodies typically associated with internal service probe responses.
