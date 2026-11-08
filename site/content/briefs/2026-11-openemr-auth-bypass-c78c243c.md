---
brief_id: brief-2026-11-08-openemr-auth-bypass-c78c243c
event_id: brief-2026-11-08-openemr-auth-bypass-c78c243c
revision: 1
activity_at: "2026-11-08T15:36:08Z"
title: 'OpenEMR: Missing authorization in patient recall records (CVE-2026-124477)'
slug: 2026-11-openemr-auth-bypass-c78c243c
description: OpenEMR versions prior to 8.3.0 are vulnerable to an authorization bypass allowing authenticated, low-privileged users to delete arbitrary patient recall records via the delete_Recall action.
date: "2026-11-08T15:36:08Z"
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
  validation_status: Source-verified
cpes:
  - cpe:2.3:a:open-emr:openemr:*:*:*:*:*:*:*:*
vendors:
  - OpenEMR
products:
  - OpenEMR (< 8.3.0)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: OpenEMR before 8.3.0 contains a missing authorization vulnerability that allows low-privileged authenticated users to delete arbitrary patient recall records
    confidence_band: high
cves:
  - id: CVE-2026-124477
    cvss: 8.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-124477
rules:
  - title: Detect CVE-2026-124477 Exploitation - Unauthorized Patient Recall Deletion
    description: Detects exploitation of CVE-2026-124477 by monitoring POST requests to the message save endpoint that invoke the delete_Recall action
    platform: sigma
    severity: high
    tactics:
      - privilege-escalation
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
    - action: Patch OpenEMR to 8.3.0 or later
      owner: IT Operations
      due: 48h
      evidence: Vulnerability addressed in OpenEMR versions 8.3.0 and above
    - action: Hunt for historical exploitation of the delete_Recall action
      owner: SOC
      due: 24h
      evidence: Exploitation involves POST requests to /interface/main/messages/save.php
  mitigation_plan:
    - priority: immediate
      action: Upgrade to OpenEMR 8.3.0
      owner: IT Operations
      addresses: CVE-2026-124477
      evidence: Source indicates version 8.3.0 as the fix
---

OpenEMR versions before 8.3.0 contain a missing authorization vulnerability (CVE-2026-124477) that allows low-privileged authenticated users to delete arbitrary patient recall records. The vulnerability is triggered by sending a POST request to `/interface/main/messages/save.php` with the `delete_Recall` action, targeting a specific patient ID (pid) and record ID (r_ID). The application fails to perform necessary Access Control List (ACL) or ownership checks before processing the deletion, leading to unauthorized data loss.

## Impact

Successful exploitation allows an authenticated attacker to delete patient recall data, potentially causing medical records disruption or data loss.

## Recommendation

* Upgrade OpenEMR to version 8.3.0 or later immediately to resolve the missing authorization check.
* Audit access logs for unauthorized access or execution of the `delete_Recall` action by low-privileged user accounts.
