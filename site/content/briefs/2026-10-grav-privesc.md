---
title: Privilege Escalation in Grav grav-plugin-api
slug: 2026-10-grav-privesc
description: A privilege escalation vulnerability (CVE-2026-109317) in the Grav grav-plugin-api plugin before version 1.0.36 allows users with delegated management permissions to obtain super-admin access.
date: "2026-10-12T18:35:09Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:getgrav:grav-plugin-api:*:*:*:*:*:*:*:*
tags:
  - privilege-escalation
  - cms
  - web-application
vendors:
  - Grav
products:
  - grav-plugin-api (< 1.0.36)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Grav grav-plugin-api before 1.0.36 contains a privilege escalation vulnerability that allows delegated user managers to obtain super-admin access.
    confidence_band: high
cves:
  - id: CVE-2026-109317
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-109317
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Grav grav-plugin-api to 1.0.36 or later
      owner: IT Operations
      due: 24h
      evidence: Source explicitly mandates upgrading to 1.0.36 to remediate CVE-2026-109317
  hunt_leads:
    - lead: Audit account access maps or invitation history for manual insertion of positive scalar grants
      technique_id: T1068
      data_needed:
        - Application logs related to user management and API grants
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Attacker manipulates account access maps to satisfy requireSuper checks
  mitigation_plan:
    - priority: immediate
      action: Restrict api.users.write permissions to verified super-admins
      owner: IT Operations
      addresses: CVE-2026-109317
      evidence: Vulnerability requires api.users.write access to trigger
---

The Grav grav-plugin-api plugin, in versions prior to 1.0.36, contains a privilege escalation vulnerability that stems from improper validation of admin or API parent grants. Attackers who possess the 'api.users.write' permission can modify account access maps or invitations. By manipulating these structures to include positive scalar values, an attacker can coerce the permission resolver to incorrectly satisfy 'requireSuper' authorization checks. This flaw allows a standard user manager to elevate their privileges to that of a super-admin, granting them access to restricted API endpoints that should be protected. This vulnerability poses a significant risk to the integrity and confidentiality of the Grav management interface, as it allows for unauthorized administrative control over the application.

## Impact

Successful exploitation allows a user with existing, limited 'api.users.write' permissions to escalate their account status to a super-admin level. This provides complete control over the Grav instance's API, potentially leading to unauthorized data exfiltration, system configuration changes, or the compromise of all hosted content. Organizations using the Grav CMS with the affected plugin are vulnerable if they have delegated user management responsibilities to non-administrative accounts.

## Recommendation

* Patch the Grav grav-plugin-api plugin by upgrading to version 1.0.36 or later immediately.
* Audit existing user accounts and access maps for unauthorized modification or suspicious assignment of 'admin' or 'api' parent grants.
* Restrict 'api.users.write' permissions to only the most trusted administrative accounts until the upgrade is applied.
