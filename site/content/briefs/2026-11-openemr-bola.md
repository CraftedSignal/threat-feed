---
brief_id: brief-2026-11-08-openemr-bola
event_id: brief-2026-11-08-openemr-bola
revision: 1
activity_at: "2026-11-08T15:35:53Z"
title: 'OpenEMR: Broken object-level authorization in SOAP note API (CVE-2026-124473)'
slug: 2026-11-openemr-bola
description: OpenEMR versions prior to 8.3.0 contain a broken object-level authorization vulnerability that allows authenticated users to overwrite clinical notes belonging to other patients by manipulating the SOAP note ID in API requests.
date: "2026-11-08T15:35:53Z"
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
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1565
    technique_name: Data Manipulation
    evidence: Authenticated users with encounters/notes permission can send PUT requests ... with another patient's sid to overwrite that clinical note and reassign its pid.
    confidence_band: high
cves:
  - id: CVE-2026-124473
    cvss: 7.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-124473
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch OpenEMR to version 8.3.0 or later
      owner: IT Operations
      due: 72h
      evidence: Vulnerability addressed in versions 8.3.0 and later
  hunt_leads:
    - lead: Identify PUT requests to /api/patient/*/encounter/*/soap_note/* where the authenticated user context does not match typical access scope for the targeted patient/encounter IDs.
      technique_id: T1565
      data_needed:
        - Web server access logs (method, URI, user_id, status_code)
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Authenticated users with encounters/notes permission can send PUT requests to /api/patient/:pid/encounter/:eid/soap_note/:sid
  mitigation_plan:
    - priority: immediate
      action: Upgrade OpenEMR to 8.3.0
      owner: IT Operations
      addresses: CVE-2026-124473
      evidence: NIST NVD vulnerability details
---

OpenEMR versions prior to 8.3.0 contain a broken object-level authorization (BOLA) vulnerability in the SOAP note update API. The application fails to verify that the provided SOAP note ID (sid) is associated with the patient and encounter specified in the request URI. An authenticated user with existing "encounters/notes" permissions can perform a PUT request to the API, allowing them to overwrite existing clinical notes and reassign the records to a different patient ID.

## Impact

Successful exploitation results in unauthorized modification of clinical records and data integrity compromise within the electronic medical record system. 

## Recommendation

* Upgrade OpenEMR to version 8.3.0 or later to resolve the underlying authorization logic flaw.
* Audit web server logs for PUT requests to the SOAP note API where the requested Patient ID (pid) or Encounter ID (eid) may be inconsistent with access patterns or user-specific permissions.
* Review access control logs for users with "encounters/notes" permissions to identify anomalous update activity.
