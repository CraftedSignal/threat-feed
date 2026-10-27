---
brief_id: brief-2026-10-27-openpanel-sql-injection
event_id: brief-2026-10-27-openpanel-sql-injection
revision: 1
activity_at: "2026-10-27T01:51:59Z"
title: 'OpenPanel: SQL injection in profile.values (CVE-2026-116808)'
slug: 2026-10-openpanel-sql-injection
description: OpenPanel versions prior to 3.0.0 contain an SQL injection vulnerability in the profile.values endpoint that allows authenticated attackers to bypass cross-tenant controls and exfiltrate data from other projects.
date: "2026-10-27T01:51:59Z"
lastmod: "2026-10-27T01:52:13Z"
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
  validation_status: Source-verified information disclosure vulnerability in specific query endpoint.
cpes:
  - cpe:2.3:a:openpanel:openpanel:*:*:*:*:*:*:*:*
tags:
  - web-application
  - sql-injection
  - cve-2026-116808
  - information-disclosure
  - tRPC
  - openpanel
vendors:
  - OpenPanel
products:
  - OpenPanel (< 3.0.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: OpenPanel before 3.0.0 contains an sql injection vulnerability that allows authenticated users to read cross-tenant data by supplying a crafted property parameter to profile.values.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1592
    technique_name: Gather Victim Host Information
    evidence: Attackers can call the notification.rules tRPC query to retrieve Slack bot tokens, webhook URLs, and authorization headers for use against external systems.
    confidence_band: high
cves:
  - id: CVE-2026-116808
    cvss: 7.2
    kev_status: "false"
  - id: CVE-2026-116819
    cvss: 8.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-116808
  - https://nvd.nist.gov/vuln/detail/CVE-2026-116819
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade OpenPanel to version 3.0.0 or later.
      owner: IT Operations
      due: 48h
      evidence: Vulnerability is patched in version 3.0.0.
    - action: Upgrade OpenPanel to version 3.0.0 or later
      owner: IT Operations
      due: 48h
      evidence: OpenPanel before 3.0.0 contains an information disclosure vulnerability
  hunt_leads:
    - lead: Inspect application logs for the profile.values endpoint containing SQL injection patterns in the property parameter.
      technique_id: T1190
      data_needed:
        - Application server request logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Attackers can inject a SELECT expression with their own FROM/WHERE clauses and comment out the project_id scope to exfiltrate other projects profiles, events, and sessions.
    - lead: Identify excessive or repeated requests to the notification.rules tRPC query endpoint from non-administrative project users
      technique_id: T1592
      data_needed:
        - Web server access logs or tRPC request logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Attackers can call the notification.rules tRPC query to retrieve Slack bot tokens
  mitigation_plan:
    - priority: immediate
      action: Upgrade OpenPanel to 3.0.0.
      owner: IT Operations
      addresses: CVE-2026-116808
      evidence: NVD vulnerability report
    - priority: immediate
      action: Apply patch to version 3.0.0
      owner: IT Operations
      addresses: CVE-2026-116819
      evidence: OpenPanel before 3.0.0 contains an information disclosure vulnerability
updates:
  - at: "2026-10-27T01:52:13Z"
    level: L2
    summary: added coverage for OpenPanel (< 3.0.0)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-116819
---

OpenPanel versions prior to 3.0.0 are affected by an SQL injection vulnerability. Authenticated users can manipulate the 'property' parameter within the 'profile.values' endpoint to inject arbitrary SQL expressions. This allows attackers to bypass multi-tenancy protections by including custom SELECT statements, FROM/WHERE clauses, and SQL comments to isolate and exfiltrate profiles, events, and session data belonging to other projects.

## Impact

Successful exploitation allows for unauthorized cross-tenant data access, specifically the exfiltration of sensitive information including user profiles, event logs, and session data stored within the OpenPanel platform.

## Recommendation

- Upgrade all instances of OpenPanel to version 3.0.0 or later to remediate CVE-2026-116808.
- Implement request logging on the 'profile.values' endpoint to audit 'property' parameter values for potential SQL injection characters such as comment sequences (--) or SQL keywords (SELECT, UNION, FROM).
