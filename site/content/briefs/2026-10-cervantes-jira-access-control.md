---
brief_id: brief-2026-10-24-cervantes-jira-access-control
event_id: brief-2026-10-24-cervantes-jira-access-control
revision: 1
activity_at: "2026-10-24T10:12:51Z"
title: 'Cervantes: Broken access control in JiraController (CVE-2026-115975)'
slug: 2026-10-cervantes-jira-access-control
description: Cervantes version v1.3-beta contains a broken access control vulnerability in the JiraController component allowing unauthorized manipulation of Jira tickets across projects.
date: "2026-10-24T10:12:51Z"
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
  validation_status: Source verified
cpes:
  - cpe:2.3:a:cervantes:cervantes:1.3:beta:*:*:*:*:*:*
vendors:
  - Cervantes
products:
  - Cervantes (v1.3-beta)
cves:
  - id: CVE-2026-115975
    cvss: 7.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-115975
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Identify all instances of Cervantes v1.3-beta in the environment
      owner: IT Operations
      due: 24h
      evidence: Cervantes version v1.3-beta contains a broken access control vulnerability
  hunt_leads:
    - lead: Monitor for suspicious Jira ticket modification activity originating from the Cervantes application service account
      data_needed:
        - Jira audit logs (ticket creation/modification)
        - Cervantes application logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: This flaw allows unauthorized users to manipulate Jira tickets (create, edit, or delete) associated with vulnerabilities in projects they should not have access to
  mitigation_plan:
    - priority: immediate
      action: Upgrade to a patched version of Cervantes once released by the vendor
      owner: IT Operations
      addresses: CVE-2026-115975
      evidence: Broken access control in JiraController in Cervantes version v1.3-beta
---

Cervantes version v1.3-beta is affected by a broken access control vulnerability in the JiraController component, tracked as CVE-2026-115975. This flaw permits an authenticated user to perform unauthorized actions including creating, editing, or deleting Jira tickets related to vulnerabilities in projects outside their assigned scope.

## Impact
Successful exploitation allows unauthorized modification of project data, which can compromise the integrity of vulnerability management workflows and lead to project-wide interference.

## Recommendation
Inventory all instances of Cervantes v1.3-beta within the environment. If identified, restrict access to the JiraController component or upgrade to a patched version once provided by the vendor.
