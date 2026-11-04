---
brief_id: brief-2026-11-04-herowatch-idor
event_id: brief-2026-11-04-herowatch-idor
revision: 1
activity_at: "2026-11-04T08:39:57Z"
title: 'About Time Technologies Herowatch Go Server: Insecure Direct Object Reference (CVE-2026-121817)'
slug: 2026-11-herowatch-idor
description: An Insecure Direct Object Reference (IDOR) vulnerability in About Time Technologies Herowatch Go Server allows authenticated remote attackers to access or modify data belonging to other users.
date: "2026-11-04T08:39:57Z"
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
  validation_status: Source identifies vulnerability and impact; environment validation required to identify specific affected endpoints.
cpes:
  - cpe:2.3:a:about_time_technologies:herowatch_go_server:*:*:*:*:*:*:*:*
tags:
  - idor
  - web-application-vulnerability
vendors:
  - About Time Technologies
products:
  - Herowatch Go Server
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: An authenticated remote attacker can manipulate specific parameters within the application to access or execute functions on behalf of other users.
    confidence_band: high
cves:
  - id: CVE-2026-121817
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-121817
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Review vendor advisories from About Time Technologies for patch availability.
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-121817 vulnerability notification.
  hunt_leads:
    - lead: Analyze web server logs for high-frequency access to object identifiers that do not belong to the active authenticated session ID.
      technique_id: T1068
      data_needed:
        - Web server access logs
        - Application-level session/request audit logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Authenticated remote attackers can modify specific parameters to access or operate other users' data.
  mitigation_plan:
    - priority: immediate
      action: Implement strict server-side authorization checks on all resource-accessing API endpoints to ensure the requesting user owns or has permission to access the requested object ID.
      owner: Security Engineering
      addresses: CVE-2026-121817
      evidence: Insecure Direct Object Reference (IDOR) vulnerability.
---

CVE-2026-121817 is an Insecure Direct Object Reference (IDOR) vulnerability affecting the Herowatch Go Server developed by About Time Technologies. The vulnerability allows an authenticated attacker to manipulate specific request parameters to access, modify, or perform actions on data associated with other user accounts. The vulnerability carries a CVSS v3.1 base score of 7.5.

## Impact
Successful exploitation allows for unauthorized data access and unauthorized execution of functions on behalf of other users within the application environment.

## Recommendation
- Audit access control implementations within the Herowatch Go Server API endpoints.
- Review authentication logs and API request history for anomalous patterns where a single authenticated session accesses objects (IDs, usernames, or database keys) typically associated with multiple unique user accounts.
- Apply patches provided by About Time Technologies for Herowatch Go Server as soon as they become available.
