---
brief_id: brief-2026-11-08-openemr-auth-bypass-ba3c3f5b
event_id: brief-2026-11-08-openemr-auth-bypass-ba3c3f5b
revision: 1
activity_at: "2026-11-08T15:36:23Z"
title: 'OpenEMR: Incorrect authorization in prescription REST API (CVE-2026-124483)'
slug: 2026-11-openemr-auth-bypass-ba3c3f5b
description: OpenEMR versions prior to 8.4.0 contain an incorrect authorization flaw in the prescription REST API, allowing authenticated staff to forge or deactivate patient prescriptions.
date: "2026-11-08T15:36:23Z"
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
  validation_status: CVE-2026-124483 confirmed by NVD
cpes:
  - cpe:2.3:a:open-emr:openemr:*:*:*:*:*:*:*:*
tags:
  - web-application
  - medical-software
  - authorization-bypass
  - cve-2026-124483
vendors:
  - OpenEMR
products:
  - OpenEMR (< 8.4.0)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Authenticated staff users can reuse the UI-exposed APICSRFTOKEN to enumerate prescription UUIDs, forge prescriptions for arbitrary patients, and deactivate existing prescriptions tenant-wide.
    confidence_band: high
cves:
  - id: CVE-2026-124483
    cvss: 8.3
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-124483
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade OpenEMR to version 8.4.0 or later
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-124483 advisory
  hunt_leads:
    - lead: Identify unauthorized REST API calls to prescription endpoints by users with only read-only Medical/History permissions
      technique_id: T1068
      data_needed:
        - Web server access logs
        - OpenEMR application audit logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Authenticated staff users can reuse the UI-exposed APICSRFTOKEN to enumerate prescription UUIDs
  mitigation_plan:
    - priority: immediate
      action: Upgrade OpenEMR to version 8.4.0
      owner: IT Operations
      addresses: CVE-2026-124483
      evidence: NVD CVE-2026-124483
---

OpenEMR versions before 8.4.0 contain an incorrect authorization vulnerability in the prescription REST API. The API improperly validates requests by checking the patients.med ACL instead of the intended patients.rx ACL and fails to verify required permission bits. This allows an authenticated staff user with basic read-only access to perform unauthorized actions, including the enumeration of prescription UUIDs, the forging of prescriptions for any patient, and the deactivation of existing prescriptions across the system.

## Impact

Successful exploitation allows authenticated staff users to manipulate prescription data, which could result in unauthorized medical prescriptions or the disruption of existing patient care. The scope of the vulnerability is tenant-wide.

## Recommendation

- Upgrade OpenEMR to version 8.4.0 or later to apply the fix for CVE-2026-124483.
- Until patching is complete, audit access logs for high-frequency or unauthorized access to prescription REST API endpoints by users who do not require such access for their roles.
