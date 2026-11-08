---
brief_id: brief-2026-11-08-openemr-idor
event_id: brief-2026-11-08-openemr-idor
revision: 1
activity_at: "2026-11-08T15:31:47Z"
title: 'OpenEMR: Insecure direct object reference in OnsitePortalActivityController (CVE-2026-124447)'
slug: 2026-11-openemr-idor
description: OpenEMR versions prior to 8.3.0 contain an Insecure Direct Object Reference vulnerability in the OnsitePortalActivityController::Update() function that allows authenticated portal patients to access, modify, and assume ownership of records belonging to other patients.
date: "2026-11-08T15:31:47Z"
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
    evidence: Authenticated portal patients can ... take ownership of the record.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1565.002
    technique_name: Transmitted Data Manipulation
    evidence: overwrite narratives and status, and take ownership of the record.
    confidence_band: high
cves:
  - id: CVE-2026-124447
    cvss: 8.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-124447
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade OpenEMR to version 8.3.0 or later.
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-124447 advisory remediation.
  hunt_leads:
    - lead: Identify anomalies in API request patterns to the OnsitePortalActivityController, specifically looking for users successfully modifying records that do not align with their expected patient ID or session history.
      technique_id: T1565.002
      data_needed:
        - Web server access logs
        - OpenEMR application/audit logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Vulnerability occurs in OnsitePortalActivityController::Update() via PUT requests.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to OpenEMR 8.3.0
      owner: IT Operations
      addresses: CVE-2026-124447
      evidence: NVD CVE-2026-124447 advisory
---

OpenEMR versions before 8.3.0 are susceptible to an Insecure Direct Object Reference (IDOR) vulnerability located in the `OnsitePortalActivityController::Update()` function. The application fails to validate whether the authenticated patient ID matches the record owner ID. An attacker with a valid patient portal account can manipulate PUT requests to the `onsiteportalactivity` API by specifying arbitrary activity IDs alongside their own patient ID. This leads to the unauthorized disclosure of `tableArgs` and `checksum` data, as well as the ability to overwrite activity narratives and status, effectively allowing the attacker to assume ownership of another patient's medical activity records.

## Impact

Successful exploitation allows unauthorized disclosure of sensitive medical activity data, modification of existing record narratives and status fields, and account-level record takeover within the OpenEMR patient portal.

## Recommendation

* Upgrade OpenEMR to version 8.3.0 or later to include the fix for CVE-2026-124447.
* Audit web server logs for suspicious PUT requests to the `onsiteportalactivity` API endpoint, specifically monitoring for instances where the authenticated user ID is linked to record IDs that do not belong to that session context.
