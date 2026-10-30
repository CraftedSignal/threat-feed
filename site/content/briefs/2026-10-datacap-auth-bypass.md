---
brief_id: brief-2026-10-30-datacap-auth-bypass
event_id: brief-2026-10-30-datacap-auth-bypass
revision: 1
activity_at: "2026-10-30T15:31:18Z"
title: 'DataCap: Missing authorization privilege escalation (CVE-2026-119654)'
slug: 2026-10-datacap-auth-bypass
description: DataCap versions 2025.1.1 and earlier are vulnerable to a missing authorization flaw that allows authenticated users to escalate privileges via administrative API calls.
date: "2026-10-30T15:31:18Z"
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
  validation_status: Detection logic validated against source description
cpes:
  - cpe:2.3:a:datacap:datacap:*:*:*:*:*:*:*:*
vendors:
  - DataCap
products:
  - DataCap (<= 2025.1.1)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: DataCap through 2025.1.1 contains a missing authorization vulnerability that allows any authenticated user to escalate privileges by calling administrative role and menu management APIs.
    confidence_band: high
cves:
  - id: CVE-2026-119654
    cvss: 8.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-119654
rules:
  - title: Detect CVE-2026-119654 Exploitation - Unauthorized API Role Allocation
    description: Detects exploitation of CVE-2026-119654 where an authenticated user makes a PUT request to the administrative allocation role API endpoint.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Hunt for PUT requests to /api/v1/user/allocationRole in webserver logs
      owner: SOC
      due: 24h
      evidence: Vulnerability allows privilege escalation via PUT requests to this specific endpoint
  hunt_leads:
    - lead: Identify accounts created within the last 30 days that have been assigned administrative roles
      technique_id: T1068
      data_needed:
        - DataCap application audit logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Vulnerability specifically enables self-registered accounts to escalate privileges
  mitigation_plan:
    - priority: immediate
      action: Apply security patches for DataCap as released by the vendor
      owner: IT Operations
      addresses: CVE-2026-119654
      evidence: Vulnerability allows full instance control
---

DataCap through version 2025.1.1 contains a missing authorization vulnerability in administrative role and menu management APIs. An authenticated user, including one with a self-registered account, can perform unauthorized privilege escalation by sending a PUT request to the '/api/v1/user/allocationRole' endpoint to assign themselves the administrator role, resulting in full control of the instance.

## Impact
Successful exploitation allows any authenticated user to gain administrative privileges, leading to full unauthorized control over the DataCap instance.

## Recommendation
- Review DataCap instance access logs for any PUT requests to '/api/v1/user/allocationRole' from non-administrative user accounts.
- Audit user role assignments in the DataCap environment to identify accounts that have been granted administrative privileges unexpectedly.
- Restrict user registration to known entities to mitigate the risk of self-registered accounts exploiting the API.
- Patch DataCap to a version beyond 2025.1.1 as soon as an update is made available by the vendor.
