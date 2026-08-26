---
title: Authorization Bypass in Kimai QuickEntry Controller
slug: 2026-08-kimai-auth-bypass
description: Kimai versions prior to 2.62.0 contain an authorization bypass vulnerability allowing authenticated users to create timesheet records for other team members without the required create_other_timesheet permission.
date: "2026-08-26T16:21:05Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Kimai
products:
  - Kimai
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Authenticated users with view_other_timesheet and edit_other_timesheet permissions can create timesheet records for team members by submitting the QuickEntry form, bypassing authorization checks enforced elsewhere.
    confidence_band: high
cves:
  - id: CVE-2026-80193
    cvss: 8.8
    epss: 0.00355
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-80193
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Kimai to version 2.62.0
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-80193 remediation requirement
  mitigation_plan:
    - priority: immediate
      action: Review access control lists for users with timesheet modification permissions
      owner: IT Operations
      addresses: CVE-2026-80193
      evidence: Source documentation of missing permission check
---

Kimai versions prior to 2.62.0 contain an authorization bypass vulnerability within the QuickEntry controller. The flaw arises because the application fails to validate the 'create_other_timesheet' permission when processing requests through this specific controller. Consequently, authenticated users who possess only 'view_other_timesheet' and 'edit_other_timesheet' permissions can successfully submit the QuickEntry form to create timesheet records for other team members, circumventing the authorization controls that are correctly enforced in other parts of the application. This vulnerability, tracked as CVE-2026-80193, carries a CVSS v3.1 base score of 8.8, posing a significant risk to organizations where timesheet accuracy and data integrity for payroll or project management are critical. Defenders should identify users with existing edit/view permissions for other employees and monitor for anomalous creation activity originating from the QuickEntry endpoint.

## Impact

Successful exploitation of this vulnerability allows unauthorized modification of timesheet records for arbitrary team members, potentially leading to manipulated payroll calculations, inaccurate project billing, and a violation of organizational access control policies. The impact is primarily focused on data integrity within the Kimai platform, affecting any sector utilizing Kimai for labor tracking.

## Recommendation

- Upgrade Kimai instances to version 2.62.0 or later immediately to patch the missing permission check in the QuickEntry controller.
- Audit logs for timesheet entries created via the QuickEntry form by users who do not possess the explicit 'create_other_timesheet' permission.
- Review and tighten existing 'view_other_timesheet' and 'edit_other_timesheet' permissions for non-administrative users to minimize the impact window until patching is complete.
