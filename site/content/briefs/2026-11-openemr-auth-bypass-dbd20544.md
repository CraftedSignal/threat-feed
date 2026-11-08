---
brief_id: brief-2026-11-08-openemr-auth-bypass-dbd20544
event_id: brief-2026-11-08-openemr-auth-bypass-dbd20544
revision: 1
activity_at: "2026-11-08T17:30:44Z"
title: 'OpenEMR: Missing authorization in billing module (CVE-2026-124471)'
slug: 2026-11-openemr-auth-bypass-dbd20544
description: OpenEMR versions prior to 8.3.0 contain an authorization bypass in the sl_eob_invoice.php script that allows authenticated users to read and modify arbitrary billing records via parameter manipulation.
date: "2026-11-08T17:30:44Z"
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
  validation_status: Needs environment validation of log accessibility for the specific PHP endpoint.
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
    evidence: The vulnerability allows any authenticated user to access and manipulate sensitive billing data across different patient encounters.
    confidence_band: high
cves:
  - id: CVE-2026-124471
    cvss: 8.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-124471
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch OpenEMR to version 8.3.0 or later.
      owner: IT Operations
      due: 72h
      evidence: CVE-2026-124471 remediated in version 8.3.0.
  hunt_leads:
    - lead: Identify abnormal request volume or parameter enumeration to sl_eob_invoice.php.
      technique_id: T1068
      data_needed:
        - Web server access logs (cs-uri-stem, cs-uri-query, cs-username)
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Attackers can iterate the id parameter to read patient names and billing notes.
  mitigation_plan:
    - priority: immediate
      action: Restrict network access to the OpenEMR billing interface to authorized subnets.
      owner: IT Operations
      addresses: CVE-2026-124471
      evidence: Authorization bypass occurs within the billing module interface.
---

OpenEMR versions prior to 8.3.0 are vulnerable to a missing authorization flaw in 'interface/billing/sl_eob_invoice.php'. The vulnerability allows an authenticated user to perform unauthorized operations by manipulating the 'id' parameter in HTTP requests. Impacted operations include reading patient names and billing notes, posting payments, applying adjustments, and deleting billing entries for any encounter regardless of the user's assigned permissions.

## Impact
Successful exploitation allows for unauthorized data disclosure (PII/PHI) and modification of financial and clinical billing records across all patient encounters.

## Recommendation
* Upgrade OpenEMR to version 8.3.0 or later to remediate CVE-2026-124471.
* Audit access logs for the 'interface/billing/sl_eob_invoice.php' endpoint to identify patterns of excessive or abnormal requests to the 'id' parameter by non-billing personnel.
