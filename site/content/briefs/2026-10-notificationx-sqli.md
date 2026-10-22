---
brief_id: brief-2026-10-22-notificationx-sqli
event_id: brief-2026-10-22-notificationx-sqli
revision: 1
activity_at: "2026-10-22T14:15:36Z"
title: 'NotificationX: Unauthenticated SQL injection (CVE-2022-51021)'
slug: 2026-10-notificationx-sqli
description: The NotificationX plugin for WordPress (versions 2.0.0 through 2.3.11) contains an unauthenticated SQL injection vulnerability in the REST API that allows remote attackers to perform database queries.
date: "2026-10-22T14:15:36Z"
type: threat
types:
  - threat
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: very likely
qa_status:
  verdict: pass
  validation_status: Rule definitions and metadata aligned with source.
cpes:
  - cpe:2.3:a:wpdeveloper:notificationx:*:*:*:*:*:wordpress:*:*
vendors:
  - WPDeveloper
products:
  - NotificationX (< 2.3.12)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: NotificationX plugin for WordPress 2.0.0 before 2.3.12 contains an unauthenticated SQL injection vulnerability that allows remote attackers to manipulate database queries.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Attacker can pass id[1] with crafted SQL... to extract database contents.
    confidence_band: high
cves:
  - id: CVE-2022-51021
    cvss: 8.2
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2022-51021
rules:
  - title: Detects CVE-2022-51021 Exploitation - SQL Injection in NotificationX REST API
    description: Detects exploitation attempts targeting the NotificationX plugin by monitoring for SQL injection payloads in the 'id' parameter of the REST API endpoint.
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
    - action: Upgrade NotificationX plugin to version 2.3.12 or later.
      owner: IT Operations
      due: 24h
      evidence: Source specifies fix in version 2.3.12.
  hunt_leads:
    - lead: Search web logs for requests to /wp-json/notificationx/v1/notification/ with array-style 'id' parameters.
      technique_id: T1190
      data_needed:
        - Web server access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Exploitation observed by Shadowserver Foundation.
---

The NotificationX plugin for WordPress versions 2.0.0 through 2.3.11 contains an unauthenticated SQL injection vulnerability (CVE-2022-51021). The vulnerability resides in the REST API endpoint `/wp-json/notificationx/v1/notification/{id}`. Remote attackers can exploit this by passing an array-form `id` parameter containing crafted SQL payloads alongside an API key derived from `md5(home_url())`. The unsanitized input is passed to the `Database::get_where_query` function, enabling unauthorized database interaction and information extraction.

## Impact
Successful exploitation allows for the extraction of sensitive database contents. The Shadowserver Foundation documented in-the-wild exploitation of this vulnerability starting on October 18, 2023.

## Recommendation
- Update the NotificationX plugin to version 2.3.12 or later immediately.
- Audit database logs for unusual queries originating from the REST API endpoint `/wp-json/notificationx/v1/notification/`.
- Deploy web application firewall (WAF) rules to detect and block incoming POST or GET requests to the identified vulnerable endpoint containing SQL injection patterns such as `SLEEP`, `UNION`, or `SELECT` keywords in query parameters.
