---
title: Improper Authorization in Grav Flex Objects Plugin
slug: 2026-08-grav-flex-auth
description: An improper authorization vulnerability in the Grav Flex Objects plugin API allows an authenticated user with limited administrative privileges to escalate their access and gain full site control via unauthorized password resets or group privilege modification.
date: "2026-08-14T14:12:37Z"
type: advisory
types:
  - advisory
severities:
  - medium
vendors:
  - Grav
products:
  - Flex Objects (<= 1.4.6)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation of Privilege Escalation Vulnerability
    evidence: An authenticated account... can use the generic /api/v1/flex-objects/user-accounts endpoint to change a super administrator's password, or the /api/v1/flex-objects/user-groups endpoint to grant its group admin.super, resulting in full site takeover.
    confidence_band: high
cves:
  - id: CVE-2026-72831
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-72831
rules:
  - title: Detect CVE-2026-72831 Exploitation - Authorization Bypass in Flex Objects API
    description: Detects potential exploitation of CVE-2026-72831 by monitoring API calls to user-accounts or user-groups endpoints followed by state-changing HTTP methods from lower-privileged accounts.
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
  immediate_actions:
    - action: Upgrade Flex Objects plugin to 1.4.7
      owner: IT Operations
      due: 48h
      evidence: Fixed in Flex Objects 1.4.7.
  mitigation_plan:
    - priority: immediate
      action: Review administrative user permissions
      owner: IT Operations
      addresses: CVE-2026-72831
      evidence: An authenticated account with api.access, admin.login, and users.update permissions... can use the generic /api/v1/flex-objects/user-accounts endpoint to change a super administrator's password
---

The Flex Objects plugin for Grav CMS (versions 1.4.6 and earlier) contains an incorrect authorization vulnerability in its API controller. The FlexApiController::update() method fails to enforce sufficient target-specific or field-level permissions, relying instead on broad directory-level checks. This oversight allows an attacker with existing, low-level administrative access (specifically 'api.access', 'admin.login', and 'users.update' permissions) to interact with the '/api/v1/flex-objects/user-accounts' and '/api/v1/flex-objects/user-groups' endpoints. By manipulating these endpoints, an authenticated adversary can reset the password of a super-administrator account or assign the 'admin.super' permission to their own user group. This flaw leads to complete site takeover. The vulnerability is addressed in Flex Objects version 1.4.7.

## Impact

Successful exploitation results in full administrative site takeover, allowing the attacker to modify site content, configure malicious plugins, access sensitive user data, and execute arbitrary server-side code if the environment permits. This affects any Grav CMS instance running the vulnerable Flex Objects plugin, particularly those where multiple administrative users with varying permission levels exist.

## Recommendation

* Immediately update the Flex Objects plugin to version 1.4.7 or higher.
* Audit logs for suspicious activity targeting the '/api/v1/flex-objects/user-accounts' and '/api/v1/flex-objects/user-groups' endpoints, specifically looking for password changes or group membership modifications originating from non-super-admin accounts.
* Review current user roles and ensure that the 'users.update' permission is only granted to trusted, fully authorized administrative personnel.
