---
brief_id: brief-2026-11-10-sql-injection-uri
event_id: brief-2026-11-10-sql-injection-uri
revision: 1
activity_at: "2026-11-10T11:53:10Z"
title: Detection of SQL Injection Payloads in Web Server Access Logs
slug: 2026-11-sql-injection-uri
description: This brief provides detection logic for identifying common SQL injection (SQLi) payloads embedded within HTTP GET requests in web server access logs.
date: "2026-11-10T11:53:10Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
qa_status:
  verdict: pass
tags:
  - web-application-attack
  - sql-injection
  - webserver
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Detects potential SQL injection attempts via GET requests in access logs.
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/web/webserver_generic/web_sql_injection_in_access_logs.yml
rules:
  - title: Detect SQL Injection Strings In URI
    description: Detects common SQL injection patterns in HTTP GET requests by monitoring for database-specific commands and syntax in web server access logs.
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
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma rule to identify SQLi patterns in web traffic
      owner: Detection Engineering
      due: 48h
      evidence: Rule definitions provided in source
  hunt_leads:
    - lead: Identify anomalies in cs-uri-query for high-frequency or unusual patterns
      technique_id: T1190
      data_needed:
        - webserver access logs
      priority: medium
      confidence: medium
      disposition: convert_to_detection
      evidence: Source lists keywords frequently used in SQLi payloads
---

This alert documents a detection capability for identifying SQL injection attempts targeting web applications. Attackers frequently use SQLi to query database structures, extract sensitive data, or bypass authentication mechanisms by manipulating GET request parameters. The provided detection logic specifically targets common database-specific keywords and syntax observed in web server access logs, such as `UNION SELECT`, `information_schema`, and sleep-based blind SQLi payloads.

## Recommendation

* Deploy the Sigma rule below to the SIEM or Log Management system to identify potential SQL injection attempts.
* Monitor high-frequency triggers of this rule to distinguish between actual exploitation attempts and legitimate application behavior, such as search functionality or internal vulnerability scanners.
* Integrate additional context, such as User-Agent headers, to differentiate between automated scanning tools and user-initiated browser requests.
