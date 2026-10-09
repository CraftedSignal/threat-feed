---
title: Unauthenticated SQL Injection in PHPNuxBill radius.php
slug: 2026-10-phpnuxbill-sqli
description: PHPNuxBill versions through 2025.3.20 are vulnerable to an unauthenticated time-based blind SQL injection in the radius.php FreeRADIUS REST endpoint, allowing credential and data exfiltration.
date: "2026-10-09T15:28:54Z"
lastmod: "2026-10-09T15:30:11Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:phpnuxbill:phpnuxbill:*:*:*:*:*:*:*:*
tags:
  - web-application
  - authentication-bypass
  - account-takeover
vendors:
  - PHPNuxBill
products:
  - PHPNuxBill (<= 2025.3.20)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: PHPNuxBill through 2025.3.20 contains an unauthenticated SQL injection vulnerability in the radius.php FreeRADIUS REST endpoint.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1110
    technique_name: Brute Force
    evidence: The lack of rate limiting or account lockout on the 6-digit OTP verification process allows unauthenticated attackers to brute-force the code for a known username.
    confidence_band: high
cves:
  - id: CVE-2026-108107
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-108107
  - https://nvd.nist.gov/vuln/detail/CVE-2026-108109
rules:
  - title: Detect CVE-2026-108107 - Unauthenticated SQL Injection in radius.php
    description: Detects potential time-based blind SQL injection attempts targeting the PHPNuxBill radius.php endpoint via accounting or authentication parameters
    platform: sigma
    severity: critical
    tactics:
      - exfiltration
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect Excessive OTP Reset Attempts
    description: Detects potential brute-force attempts against the password reset flow by monitoring high volumes of POST requests to system/controllers/forgot.php from the same source.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1110.001
    data_sources:
      - webserver
rules_count: 2
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Patch PHPNuxBill to version > 2025.3.20
      owner: IT Operations
      due: 24h
      evidence: Source states vulnerability exists through 2025.3.20
    - action: Deploy Sigma detection rule to monitor for SQL injection attempts against radius.php
      owner: Detection Engineering
      due: 24h
      evidence: High CVSS score indicates critical exposure
  mitigation_plan:
    - priority: immediate
      action: Restrict access to radius.php via firewall or WAF if immediate patching is not possible
      owner: IT Operations
      addresses: CVE-2026-108107
      evidence: Unauthenticated nature of the exploit
updates:
  - at: "2026-10-09T15:30:11Z"
    level: L2
    summary: 'added detection rule: Detect Excessive OTP Reset Attempts'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-108109
---

PHPNuxBill versions through 2025.3.20 contain a critical unauthenticated SQL injection vulnerability within the radius.php script. The vulnerability exists in the FreeRADIUS REST endpoint, where user-supplied parameters including username, macAddr, and nasid are passed directly into whereRaw() database queries without adequate sanitization. This flaw permits an unauthenticated attacker to execute arbitrary SQL commands against the backend database. By leveraging time-based blind SQL injection techniques, attackers can systematically infer database contents, including sensitive customer records and authentication credentials. This vulnerability represents a high risk to service providers using PHPNuxBill for RADIUS accounting and authentication, as it provides a direct vector for unauthorized data extraction.

## Impact

Successful exploitation allows unauthenticated remote attackers to extract the entire customer database, including usernames, passwords, and billing information. This results in complete loss of confidentiality regarding subscriber data and potential compromise of downstream network access credentials managed by the RADIUS server.

## Recommendation

Prioritize the identification and patching of all internet-facing instances of PHPNuxBill. Ensure all instances are updated beyond version 2025.3.20 to mitigate CVE-2026-108107. 

- Audit web server access logs for anomalous payloads containing SQL keywords (e.g., SLEEP, BENCHMARK, WAITFOR, or UNION SELECT) targeting the radius.php endpoint.
- If patching is not immediately feasible, restrict access to the radius.php endpoint at the network or web application firewall level to known-trusted RADIUS infrastructure IPs only.
