---
brief_id: brief-2026-11-03-yeti-auth-bypass
event_id: brief-2026-11-03-yeti-auth-bypass
revision: 1
activity_at: "2026-11-03T22:19:59Z"
title: 'YETI: Authentication bypass in audit router (CVE-2026-63482)'
slug: 2026-11-yeti-auth-bypass
description: The YETI Forensics Intelligence platform prior to version 2.5.1 contains an authentication bypass vulnerability allowing unauthenticated attackers to retrieve sensitive audit logs via the API.
date: "2026-11-03T22:19:59Z"
lastmod: "2026-11-03T22:20:46Z"
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
cpes:
  - cpe:2.3:a:yeti:yeti:*:*:*:*:*:*:*:*
vendors:
  - YETI
products:
  - YETI (< 2.5.1)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1592
    technique_name: Gather Victim Host Information
    evidence: An unauthenticated network attacker can use an empty, partial, or specific wildcard path to query TimelineLog records containing the actor, target_id, action, and details fields.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An authenticated low-privileged user using the default local storage backend can call POST /api/v2/tasks/export/new with a traversal name
    confidence_band: high
cves:
  - id: CVE-2026-63482
    kev_status: unknown
  - id: CVE-2026-63502
    cvss: 8.3
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-63482
  - https://nvd.nist.gov/vuln/detail/CVE-2026-63502
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade YETI to version 2.5.1 or later
      owner: IT Operations
      due: 48h
      evidence: This issue is fixed in version 2.5.1.
    - action: Upgrade YETI to version 2.5.1
      owner: IT Operations
      due: 48h
      evidence: This issue is fixed in version 2.5.1.
  hunt_leads:
    - lead: Identify unauthorized access to /api/v2/audit/timeline/ in web application logs
      technique_id: T1592
      data_needed:
        - Web server access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: An unauthenticated network attacker can use an empty, partial, or specific wildcard path to query TimelineLog records
    - lead: Hunt for directory traversal patterns in API requests
      technique_id: T1190
      data_needed:
        - Web server access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: can call POST /api/v2/tasks/export/new with a traversal name
  mitigation_plan:
    - priority: immediate
      action: Restrict network access to the YETI management interface if immediate patching is not possible
      owner: IT Operations
      addresses: CVE-2026-63482
      evidence: An unauthenticated network attacker can use an empty, partial, or specific wildcard path
    - priority: immediate
      action: Upgrade to YETI 2.5.1
      owner: IT Operations
      addresses: CVE-2026-63502
      evidence: This issue is fixed in version 2.5.1.
updates:
  - at: "2026-11-03T22:20:46Z"
    level: L2
    summary: added coverage for YETI (< 2.5.1)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-63502
---

YETI versions prior to 2.5.1 contain an authentication bypass vulnerability in the audit router. The file core/web/apiv2/audit.py fails to implement the required `auth.get_current_active_user` dependency for the `/api/v2/audit/timeline/{id}` endpoint. An unauthenticated attacker can exploit this to query sensitive TimelineLog records, which contain analyst usernames, object identifiers, and historical threat intelligence object data.

## Impact
Unauthorized exposure of operational threat intelligence, including analyst identity and sensitive object modification history.

## Recommendation
Upgrade the YETI platform to version 2.5.1 or later to apply the missing route-level authentication checks.

## Hunt Leads
- Lead: Audit access to the /api/v2/audit/timeline/ endpoint
 data_needed:
 - Web server access logs or application-level API request logs
 priority: "high"
 confidence: "high"
 disposition: "hunt_now"
 evidence: "An unauthenticated network attacker can use an empty, partial, or specific wildcard path to query TimelineLog records containing the actor, target_id, action, and details fields."
