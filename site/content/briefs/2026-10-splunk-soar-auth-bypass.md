---
brief_id: brief-2026-10-21-splunk-soar-auth-bypass
event_id: brief-2026-10-21-splunk-soar-auth-bypass
revision: 1
activity_at: "2026-10-21T23:49:25Z"
title: 'Splunk SOAR: Authentication token inference and privilege escalation (CVE-2026-76307)'
slug: 2026-10-splunk-soar-auth-bypass
description: Splunk SOAR versions prior to 8.7.0 are vulnerable to an authentication bypass where a user with restricted permissions can use the REST API to infer administrative tokens via crafted query filters.
date: "2026-10-21T23:49:25Z"
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
  validation_status: Ready for deployment
cpes:
  - cpe:2.3:a:splunk:soar:*:*:*:*:*:*:*:*
tags:
  - privilege-escalation
  - splunk
  - soar
  - cve-2026-76307
vendors:
  - Splunk
products:
  - SOAR (< 8.7.0)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: If the inferred token grants administrative access, that user could gain administrative access to the Splunk SOAR instance.
    confidence_band: high
cves:
  - id: CVE-2026-76307
    cvss: 7.2
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-76307
  - https://help.splunk.com/en/splunk-soar/soar-on-premises/rest-api-reference/7.1.0/using-the-splunk-soar-rest-api/query-for-data
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade Splunk SOAR to 8.7.0 or later
      owner: IT Operations
      due: 48h
      evidence: Vulnerability affects versions below 8.7.0
  mitigation_plan:
    - priority: immediate
      action: Revoke Users and Roles view permissions from non-administrative roles until upgrade
      owner: SOC
      addresses: CVE-2026-76307
      evidence: User holding a role with the Users and Roles view permission could use the REST API to infer authentication token values
---

Splunk SOAR versions below 8.7.0 contain an authentication vulnerability (CVE-2026-76307) that allows a user with "Users and Roles" view permissions to infer authentication tokens belonging to other users. The vulnerability arises because the REST API permits caller-controlled query filters on sensitive user record fields. By targeting these fields, a standard user can obtain tokens and potentially escalate privileges to administrative levels.

## Impact

Successful exploitation allows a non-privileged user with specific view permissions to obtain administrative authentication tokens, leading to full unauthorized control over the Splunk SOAR instance.

## Recommendation

* Upgrade Splunk SOAR to version 8.7.0 or later immediately.
* Review existing role-based access control (RBAC) configurations in Splunk SOAR to ensure that "Users and Roles" view permissions are granted only to strictly authorized personnel.
* Audit REST API logs for anomalous query patterns targeting sensitive user record fields or repetitive filter attempts.
