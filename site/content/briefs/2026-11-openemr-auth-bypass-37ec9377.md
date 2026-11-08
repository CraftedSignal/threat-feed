---
brief_id: brief-2026-11-08-openemr-auth-bypass-37ec9377
event_id: brief-2026-11-08-openemr-auth-bypass-37ec9377
revision: 1
activity_at: "2026-11-08T15:35:35Z"
title: 'OpenEMR: Missing authorization in billing notes (CVE-2026-124472)'
slug: 2026-11-openemr-auth-bypass-37ec9377
description: OpenEMR versions prior to 8.3.0 are vulnerable to a missing authorization flaw allowing authenticated low-privileged users to read and modify sensitive patient billing notes via parameter manipulation.
date: "2026-11-08T15:35:35Z"
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
    evidence: Attackers with low-privilege accounts can enumerate the patient_id parameter and submit POST requests using the embedded CSRF token to view or tamper with confidential billing data.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: OpenEMR before 8.3.0 contains a missing authorization vulnerability in interface/billing/sl_eob_patient_note.php that allows any authenticated user to read and modify patient billing notes.
    confidence_band: high
cves:
  - id: CVE-2026-124472
    kev_status: unknown
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-124472
rules:
  - title: Detect Potential CVE-2026-124472 Exploitation - Access to Billing Notes
    description: Detects unauthorized POST requests to the vulnerable billing notes endpoint.
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
    - action: Patch OpenEMR to version 8.3.0 or later.
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-124472 advisory specifies version 8.3.0 as the remediation.
  hunt_leads:
    - lead: Identify authenticated users accessing sl_eob_patient_note.php who do not have explicit billing roles.
      technique_id: T1068
      data_needed:
        - Web server access logs joined with application session/user-role logs.
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Vulnerability allows any authenticated user to reach this endpoint.
  mitigation_plan:
    - priority: immediate
      action: Upgrade OpenEMR to 8.3.0.
      owner: IT Operations
      addresses: CVE-2026-124472
      evidence: NVD source.
---

OpenEMR versions before 8.3.0 contain a missing authorization vulnerability in the script 'interface/billing/sl_eob_patient_note.php'. This vulnerability enables an authenticated user to perform unauthorized read and modification operations on patient billing notes. By manipulating the 'patient_id' parameter in HTTP POST requests and reusing legitimate CSRF tokens, a low-privilege attacker can access confidential data belonging to other patients.

## Impact

The vulnerability allows unauthorized access to and tampering with patient billing records, which constitutes a significant compromise of protected health information (PHI) and data integrity within the OpenEMR instance.

## Recommendation

- Upgrade OpenEMR to version 8.3.0 or later immediately to remediate the missing authorization check.
- Review application access logs for anomalous POST request patterns directed at 'sl_eob_patient_note.php', specifically where the 'patient_id' parameter varies rapidly or is accessed by accounts that lack administrative or billing roles.
- Audit user permissions and ensure that Principle of Least Privilege is applied to all clinical and billing staff accounts to limit the blast radius of compromised credentials.
