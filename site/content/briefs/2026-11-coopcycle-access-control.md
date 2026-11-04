---
brief_id: brief-2026-11-04-coopcycle-access-control
event_id: brief-2026-11-04-coopcycle-access-control
revision: 1
activity_at: "2026-11-04T14:47:52Z"
title: 'CoopCycle coopcycle-web: Broken access control in incident management (CVE-2026-121945)'
slug: 2026-11-coopcycle-access-control
description: CoopCycle coopcycle-web before version 6.20.1 contains a broken access control vulnerability in its incident management API that allows authenticated couriers to unauthorizedly modify or cancel orders and tasks belonging to other stores.
date: "2026-11-04T14:47:52Z"
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
  - cpe:2.3:a:coopcycle:coopcycle-web:*:*:*:*:*:*:*:*
vendors:
  - CoopCycle
products:
  - coopcycle-web (< 6.20.1)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: The application fails to properly authorize API requests for incident operations, checking only if the user has the ROLE_COURIER permission.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Attackers can enumerate sequential incident ids and use PUT /api/incidents/{id}/action to re-price, cancel or reschedule other stores' orders and tasks.
    confidence_band: high
cves:
  - id: CVE-2026-121945
    cvss: 7.6
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-121945
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade coopcycle-web to 6.20.1 or later
      owner: IT Operations
      due: 72h
      evidence: CoopCycle coopcycle-web before 6.20.1 contains a broken access control vulnerability
  hunt_leads:
    - lead: Identify high-frequency or unauthorized PUT requests to the incident API
      technique_id: T1068
      data_needed:
        - Web server access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Attackers can enumerate sequential incident ids and use PUT /api/incidents/{id}/action
  mitigation_plan:
    - priority: immediate
      action: Patch coopcycle-web to version 6.20.1
      owner: IT Operations
      addresses: CVE-2026-121945
      evidence: CoopCycle coopcycle-web before 6.20.1 contains a broken access control vulnerability
---

CoopCycle coopcycle-web before version 6.20.1 contains a broken access control vulnerability within its incident management system. The application improperly authorizes requests by only verifying the presence of the ROLE_COURIER role, failing to validate ownership or scope of the requested incident. This allows an authenticated courier to read and modify sensitive incident data across the platform.

## Impact
Unauthorized actors can enumerate incident IDs and manipulate system state by issuing PUT requests to the /api/incidents/{id}/action endpoint. Documented impacts include the ability to re-price, cancel, or reschedule orders and tasks belonging to other stores.

## Recommendation
* Upgrade coopcycle-web to version 6.20.1 or later to implement proper object-level authorization for incident operations.
* Audit application access logs for anomalous patterns of PUT requests to /api/incidents/ targeting multiple sequential or disparate ID values from single accounts.
