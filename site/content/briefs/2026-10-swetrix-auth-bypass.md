---
title: Missing Authorization Vulnerability in Swetrix Cloud
slug: 2026-10-swetrix-auth-bypass
description: Swetrix Cloud versions before 5.1.0 contain a missing authorization vulnerability in the ProjectController component that allows authenticated attackers to hijack arbitrary projects.
date: "2026-10-14T16:36:55Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:swetrix:swetrix_cloud:*:*:*:*:*:*:*:*
vendors:
  - Swetrix
products:
  - Swetrix Cloud (< 5.1.0)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: Authenticated users can exploit this to move arbitrary projects into their own organization by referencing the project's public tracking ID.
    confidence_band: high
cves:
  - id: CVE-2026-110621
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-110621
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  mitigation_plan:
    - priority: immediate
      action: Upgrade Swetrix Cloud to version 5.1.0 or later.
      owner: IT Operations
      addresses: CVE-2026-110621
      evidence: Source specifies that Swetrix Cloud before 5.1.0 contains the vulnerability.
---

Swetrix Cloud versions prior to 5.1.0 are affected by a missing authorization vulnerability within the ProjectController.addProject endpoint. This flaw allows any authenticated user to hijack arbitrary projects by moving them into their own organization. By leveraging the project's public tracking ID, an attacker can manipulate project ownership, granting them unauthorized access to sensitive analytics, modification of project configuration settings, or the ability to perform a permanent deletion of the victim project. This vulnerability represents a significant risk to data integrity and availability for users of the Swetrix platform, as it permits unauthorized cross-tenant resource manipulation.

## Impact

Successful exploitation of this vulnerability allows unauthorized users to gain full administrative or read-only control over projects belonging to other organizations. This results in the potential exposure of private analytics data and enables destructive actions such as the deletion of victim projects, directly impacting the confidentiality and availability of customer data stored within the Swetrix Cloud environment.

## Recommendation

* Upgrade Swetrix Cloud to version 5.1.0 or later immediately to address the missing authorization vulnerability in ProjectController.
* Audit project ownership logs within the Swetrix platform to identify any unauthorized transfers or unexpected changes in project association that may have occurred prior to patching.
