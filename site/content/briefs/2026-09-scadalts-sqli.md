---
title: Authenticated Blind SQL Injection in ScadaLTS
slug: 2026-09-scadalts-sqli
description: ScadaLTS 2.8.1-rc is vulnerable to an authenticated blind SQL injection via the sortBy parameter in the /api/events/search endpoint, allowing low-privileged users to exfiltrate database contents.
date: "2026-09-16T17:57:05Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:scadalts:scadalts:*:*:*:*:*:*:*:*
tags:
  - sqli
  - vulnerability
  - web-application
vendors:
  - ScadaLTS
products:
  - ScadaLTS (2.8.1-rc)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The /api/events/search endpoint accepts a JSON body containing a sortBy array. The values in this array are concatenated directly into the SQL ORDER BY clause.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: The endpoint is accessible to any authenticated user with ROLE_USER, ROLE_ADMIN, or ROLE_PUBLIC.
    confidence_band: high
cves:
  - id: CVE-2026-84859
    cvss: 6.5
references:
  - https://www.tenable.com/security/research/tra-2026-60
  - https://sploitus.com/exploit?id=CVE-2026-84859
rules:
  - title: Detect CVE-2026-84859 Exploitation Attempt
    description: Detects potential blind SQL injection attempts via the sortBy parameter in the /api/events/search endpoint
    platform: sigma
    severity: medium
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
    - action: Deploy WAF or webserver filter to identify and block POST requests to /api/events/search containing SQL keywords
      owner: SOC
      due: 24h
      evidence: Source confirms endpoint is the vector for SQL injection
  hunt_leads:
    - lead: Search web logs for POST requests to /api/events/search with unusual characters in the sortBy parameter
      technique_id: T1190
      data_needed:
        - Web access logs with POST body inspection
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Source details the injection happens via the sortBy array in the JSON body
  mitigation_plan:
    - priority: medium_term
      action: Upgrade ScadaLTS to a patched version once released by vendor
      owner: IT Operations
      addresses: CVE-2026-84859
      evidence: Vulnerability exists in 2.8.1-rc
---

ScadaLTS version 2.8.1-rc is susceptible to an authenticated blind SQL injection vulnerability, identified as CVE-2026-84859. The flaw exists within the /api/events/search endpoint, which processes a JSON body containing a sortBy array. Because these array values are concatenated directly into a SQL ORDER BY clause without adequate sanitization or parameterization, an attacker can manipulate database queries. Any user with low-level privileges, including the ROLE_USER role, can leverage time-based or boolean-based SQL injection techniques to extract arbitrary information from the backend database. This impact includes the potential theft of user password hashes, which facilitates further unauthorized access or account takeover. Defenders must monitor API traffic for anomalous patterns originating from authenticated accounts and prioritize patching or isolating instances running the 2.8.1-rc build.

## Impact

Successful exploitation grants an authenticated attacker unauthorized read access to the ScadaLTS database. This enables the exfiltration of sensitive information, specifically user credential hashes, which could lead to wider system compromise across the Industrial Control System (ICS) environments where ScadaLTS is deployed.

## Recommendation

- Monitor webserver access logs for anomalous JSON payloads targeting the /api/events/search endpoint.
- Audit user roles and limit access to API endpoints to only necessary personnel to reduce the surface area for this authenticated exploit.
- Review all database query patterns for evidence of SQL injection, specifically looking for unusual characters or SQL syntax (e.g., SLEEP, UNION, CASE) within the sortBy array parameters.
- Patch or upgrade ScadaLTS to a version beyond 2.8.1-rc once a vendor-provided secure version is released.
