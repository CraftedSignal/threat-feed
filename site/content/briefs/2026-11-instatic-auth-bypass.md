---
brief_id: brief-2026-11-10-instatic-auth-bypass
event_id: brief-2026-11-10-instatic-auth-bypass
revision: 1
activity_at: "2026-11-10T02:05:01Z"
title: 'Instatic: Authorization bypass in handleRowAuthor (CVE-2026-125398)'
slug: 2026-11-instatic-auth-bypass
description: Instatic versions prior to 0.0.21 contain an authorization bypass vulnerability allowing authenticated users with limited permissions to read and modify system-table rows via direct API interaction.
date: "2026-11-10T02:05:01Z"
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
  - cpe:2.3:a:instatic:instatic:*:*:*:*:*:*:*:*
vendors:
  - Instatic
products:
  - Instatic (< 0.0.21)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Authenticated users with limited permissions can bypass table-level access control checks to read system-table rows and reassign their authors.
    confidence_band: high
cves:
  - id: CVE-2026-125398
    cvss: 7.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-125398
rules:
  - title: Detect Potential CVE-2026-125398 Exploitation - PATCH to Row Author Endpoint
    description: Detects PATCH requests to the author modification endpoint which may indicate exploitation of the authorization bypass in Instatic
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
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch Instatic to version 0.0.21 or later.
      owner: IT Operations
      due: 48h
      evidence: Instatic before 0.0.21 contains an authorization bypass vulnerability
  hunt_leads:
    - lead: Identify successful PATCH requests to the /admin/api/cms/data/rows/*/author endpoint from accounts without system administrator roles.
      technique_id: T1068
      data_needed:
        - Web server access logs
        - Application audit logs linking user ID to permissions
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Attackers holding content.edit.any but lacking data.system.tables.read can send PATCH requests to /admin/api/cms/data/rows/:id/author
  mitigation_plan:
    - priority: immediate
      action: Upgrade Instatic to 0.0.21.
      owner: IT Operations
      addresses: CVE-2026-125398
      evidence: Instatic before 0.0.21 contains an authorization bypass
---

Instatic versions before 0.0.21 contain an authorization bypass vulnerability within the handleRowAuthor function. The vulnerability arises because the application uses an insecure data retrieval method, getDataRow(), instead of the required loadRowForAccess() method, which correctly enforces table-level access controls. An authenticated user possessing the 'content.edit.any' permission, but lacking the 'data.system.tables.read' permission, can leverage this flaw to access restricted data or reassign authorship.

## Impact

The vulnerability allows unauthorized authenticated users to bypass table-level access controls, specifically enabling the reading of system-table rows and the modification of row authorship. 

## Recommendation

- Upgrade Instatic to version 0.0.21 or later to remediate the vulnerable handleRowAuthor logic.
- Review audit logs for unauthorized PATCH requests directed at the /admin/api/cms/data/rows/:id/author endpoint, specifically from users lacking system-level data permissions.
