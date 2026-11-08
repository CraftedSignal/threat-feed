---
brief_id: brief-2026-11-08-openemr-idor-db815b70
event_id: brief-2026-11-08-openemr-idor-db815b70
revision: 1
activity_at: "2026-11-08T15:32:29Z"
title: 'OpenEMR: Insecure Direct Object Reference in encounter-form endpoints (CVE-2026-124459)'
slug: 2026-11-openemr-idor-db815b70
description: OpenEMR versions prior to 8.3.0 are susceptible to an Insecure Direct Object Reference (IDOR) vulnerability that allows authenticated users to access and modify clinical records belonging to other patients by enumerating form IDs.
date: "2026-11-08T15:32:29Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:open-emr:openemr:*:*:*:*:*:*:*:*
vendors:
  - OpenEMR
products:
  - OpenEMR (< 8.3.0)
cves:
  - id: CVE-2026-124459
    cvss: 8.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-124459
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade OpenEMR to version 8.3.0 or later.
      owner: IT Operations
      due: 48h
      evidence: OpenEMR before 8.3.0 contains an insecure direct object reference vulnerability.
  hunt_leads:
    - lead: Identify authenticated users accessing or saving a high volume of sequential encounter form IDs.
      technique_id: T1595.002
      data_needed:
        - Web server access logs or application logs containing requested URLs, source UserID, and form_id parameters.
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Authenticated clinical users can enumerate sequential form id values in requests such as soap/view.php and save.php.
  mitigation_plan:
    - priority: immediate
      action: Apply OpenEMR 8.3.0 update.
      owner: IT Operations
      addresses: CVE-2026-124459
      evidence: OpenEMR before 8.3.0 contains an insecure direct object reference vulnerability in many encounter-form view and save endpoints.
---

OpenEMR versions before 8.3.0 contain an insecure direct object reference (IDOR) vulnerability in multiple encounter-form view and save endpoints. These endpoints fail to perform patient or encounter ownership validation checks. An authenticated clinical user can leverage this by incrementing sequential form ID values within HTTP requests to view or overwrite clinical data belonging to other patients.

## Impact

Successful exploitation allows an authenticated attacker to read sensitive clinical records and modify or overwrite medical data belonging to other patients, leading to potential data corruption and unauthorized information disclosure.

## Recommendation

* Upgrade OpenEMR to version 8.3.0 or later immediately to patch the missing ownership checks.
* Restrict access to clinical form endpoints for non-clinical user roles if the update cannot be applied immediately.
* Implement granular auditing of access to encounter-form endpoints to identify anomalous enumeration patterns.
