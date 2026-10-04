---
title: SQL Injection in mooSocial via Product Rating
slug: 2026-10-moosocial-sqli
description: mooSocial versions up to 3.2.4 are vulnerable to remote SQL injection via the rating argument in the /stores/all-products endpoint, with public exploit code currently available.
date: "2026-10-04T14:52:51Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
cpes:
  - cpe:2.3:a:moosocial:moosocial:*:*:*:*:*:*:*:*
tags:
  - web-vulnerability
  - sqli
  - remote-execution
vendors:
  - mooSocial
products:
  - mooSocial (<= 3.2.4)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The attack may be initiated remotely.
    confidence_band: high
cves:
  - id: CVE-2026-105149
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-105149
rules:
  - title: Detects CVE-2026-105149 Exploitation - SQL Injection in mooSocial
    description: Detects exploitation of CVE-2026-105149 by identifying SQL injection payloads in the rating parameter of the /stores/all-products endpoint.
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
    - action: Review web access logs for requests to /stores/all-products containing SQL metacharacters
      owner: SOC
      due: 24h
      evidence: NVD vulnerability description
  mitigation_plan:
    - priority: immediate
      action: Restrict access to /stores/all-products via WAF or web server configuration
      owner: IT Operations
      addresses: CVE-2026-105149
      evidence: Vulnerability analysis
---

A SQL injection vulnerability has been identified in mooSocial versions up to 3.2.4, which allows remote, unauthenticated attackers to execute arbitrary SQL commands against the underlying database. The vulnerability exists within the processing logic of the /stores/all-products endpoint, specifically involving the 'rating' argument. An exploit for this vulnerability has been publicly released, increasing the risk of active exploitation. The vendor has not responded to vulnerability disclosure attempts, leaving affected deployments without an official patch or guidance from the manufacturer. Defenders should assume that public exploit scripts are being utilized in opportunistic scans targeting these endpoints.

## Impact

Successful exploitation of this vulnerability leads to unauthorized database access, which may result in data exfiltration, modification, or complete database compromise. As the software is commonly used for social networking sites, potential impact includes the theft of user credentials, personal information, and session data. Given the availability of public exploits, all internet-facing instances of mooSocial 3.2.4 or earlier are at immediate risk of compromise.

## Recommendation

Detection engineering teams should monitor web access logs for suspicious patterns directed at the identified endpoint.

- Implement monitoring for HTTP requests containing SQL injection payloads targeting the /stores/all-products endpoint.
- Deploy web application firewall (WAF) rules to inspect and block inputs to the 'rating' parameter that contain SQL keywords or special characters.
- Due to the lack of an official patch, isolate affected mooSocial instances from the public internet if possible until security controls are verified.
