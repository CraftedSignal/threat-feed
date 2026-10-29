---
brief_id: brief-2026-10-29-newsmatic-sql-injection
event_id: brief-2026-10-29-newsmatic-sql-injection
revision: 1
activity_at: "2026-10-29T13:18:01Z"
title: 'Newsmatic WordPress Theme: Blind SQL Injection (CVE-2026-110184)'
slug: 2026-10-newsmatic-sql-injection
description: The Newsmatic theme for WordPress is vulnerable to unauthenticated blind SQL injection in the slug parameter, allowing remote attackers to extract sensitive database information.
date: "2026-10-29T13:18:01Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: needs_environment_validation
cpes:
  - cpe:2.3:a:newsmatic:newsmatic:*:*:*:*:*:wordpress:*:*
tags:
  - wordpress
  - sql-injection
  - web-application
  - cve-2026-110184
vendors:
  - Newsmatic
products:
  - Newsmatic (<= 1.5.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The Newsmatic theme for WordPress is vulnerable to blind SQL Injection... makes it possible for unauthenticated attackers to append additional SQL queries
    confidence_band: high
cves:
  - id: CVE-2026-110184
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-110184
rules:
  - title: Detects CVE-2026-110184 Exploitation - Blind SQL Injection via slug parameter
    description: Detects attempts to exploit blind SQL injection in the Newsmatic theme by identifying common SQL keywords and function patterns within the slug URL parameter.
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
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch Newsmatic theme to the latest version beyond 1.5.0
      owner: IT Operations
      due: 48h
      evidence: Vulnerability affects versions up to 1.5.0
  hunt_leads:
    - lead: Identify anomalies in web access logs for the slug parameter
      technique_id: T1190
      data_needed:
        - Web access logs (cs-uri-query)
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Blind SQL injection occurs via the slug parameter
  mitigation_plan:
    - priority: immediate
      action: Deploy WAF rule to filter SQL injection characters in slug parameter
      owner: SOC
      addresses: CVE-2026-110184
      evidence: Blind SQL injection in slug parameter
---

The Newsmatic theme for WordPress (versions 1.5.0 and earlier) contains a vulnerability due to improper input sanitization and lack of parameterized SQL queries. An unauthenticated attacker can exploit this via the 'slug' parameter to execute arbitrary SQL commands, leading to unauthorized database information disclosure.

## Impact
Successful exploitation allows for the extraction of sensitive information from the WordPress database by an unauthenticated attacker.

## Recommendation
- Update the Newsmatic theme for WordPress to a version patched beyond 1.5.0 immediately.
- Audit web application logs for suspicious 'slug' parameters containing SQL syntax (e.g., SELECT, UNION, SLEEP, benchmark).
- Implement a Web Application Firewall (WAF) to detect and block SQL injection patterns targeting the 'slug' parameter.
