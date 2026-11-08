---
brief_id: brief-2026-11-08-openemr-idor-f0a19413
event_id: brief-2026-11-08-openemr-idor-f0a19413
revision: 1
activity_at: "2026-11-08T15:32:12Z"
title: 'OpenEMR: Missing authorization and IDOR in oe-module-prior-authorizations (CVE-2026-124456)'
slug: 2026-11-openemr-idor-f0a19413
description: OpenEMR versions before 8.3.0 contain IDOR and authorization flaws in the oe-module-prior-authorizations module that allow authenticated users to access and modify patient records.
date: "2026-11-08T15:32:12Z"
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
  - id: CVE-2026-124456
    cvss: 7.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-124456
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade OpenEMR to version 8.3.0 or later
      owner: IT Operations
      due: 48h
      evidence: OpenEMR before 8.3.0 contains missing authorization and insecure direct object reference vulnerabilities.
  hunt_leads:
    - lead: Audit web server access logs for anomalous access to report and index scripts by low-privilege users.
      technique_id: T1068
      data_needed:
        - webserver access logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Attackers can request public/reports/list_report.php to view all patients names or submit arbitrary id values to public/index.php to overwrite records.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to version 8.3.0
      owner: IT Operations
      addresses: CVE-2026-124456
      evidence: OpenEMR before 8.3.0 contains missing authorization and insecure direct object reference vulnerabilities.
---

OpenEMR versions prior to 8.3.0 contain missing authorization and insecure direct object reference (IDOR) vulnerabilities within the `oe-module-prior-authorizations` module. These flaws allow an authenticated low-privilege user to access and manipulate sensitive patient data, including patient names, medical record numbers (MRNs), insurance details, and prior-authorization records.

## Impact

Successful exploitation allows for unauthorized disclosure of Protected Health Information (PHI) and unauthorized modification of patient prior-authorization records.

## Recommendation

* Upgrade OpenEMR to version 8.3.0 or later to apply the security fixes.
* Restrict user access to the `oe-module-prior-authorizations` module if immediate patching is not feasible.
* Monitor access logs for requests to `public/reports/list_report.php` and `public/index.php` that deviate from expected behavioral patterns for low-privilege user accounts.
