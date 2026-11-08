---
brief_id: brief-2026-11-08-openemr-broken-access-control
event_id: brief-2026-11-08-openemr-broken-access-control
revision: 1
activity_at: "2026-11-08T15:36:54Z"
title: 'OpenEMR: Broken access control in portal_payment.php (CVE-2026-124489)'
slug: 2026-11-openemr-broken-access-control
description: OpenEMR versions prior to 8.3.0 are vulnerable to broken access control, allowing authenticated, low-privileged users to modify patient identifiers to bypass billing restrictions and record fraudulent payments.
date: "2026-11-08T15:36:54Z"
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
  - id: CVE-2026-124489
    cvss: 7.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-124489
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade OpenEMR to version 8.3.0 or later
      owner: IT Operations
      due: 48h
      evidence: Vulnerability is patched in OpenEMR 8.3.0
  hunt_leads:
    - lead: Identify unauthorized access to portal_payment.php by low-privileged accounts
      technique_id: T1068
      data_needed:
        - Web server access logs containing request parameters for portal/portal_payment.php
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Low-privileged users can manipulate pid and form_pid parameters to bypass billing ACL checks
  mitigation_plan:
    - priority: immediate
      action: Upgrade to 8.3.0
      owner: IT Operations
      addresses: CVE-2026-124489
      evidence: Upgrade recommended by vendor to address access control flaw
---

OpenEMR versions before 8.3.0 contain a broken access control vulnerability in the `portal/portal_payment.php` script. An authenticated attacker with low privileges can bypass billing access control list (ACL) checks by manipulating the `pid` and `form_pid` parameters in requests. This allows unauthorized access to patient payment pages and the submission of fraudulent payment receipts, resulting in billing data corruption.

## Impact

Successful exploitation allows unauthorized users to view sensitive payment data of arbitrary patients and inject fraudulent payment records into the system, compromising the integrity of financial billing records.

## Recommendation

* Upgrade OpenEMR to version 8.3.0 or later immediately to patch the access control vulnerability in `portal_payment.php`.
* Audit billing records for entries created by low-privilege accounts, specifically looking for irregularities in `pid` and `form_pid` parameter associations.
