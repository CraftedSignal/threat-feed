---
title: wger Improper Privilege Management
slug: 2026-10-wger-privilege-escalation
description: A privilege escalation vulnerability in wger allows gym trainers to deactivate higher-privileged accounts, resulting in administrative lockout.
date: "2026-10-07T16:59:56Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:wger:wger:*:*:*:*:*:*:*:*
tags:
  - privilege-escalation
  - web-application
  - cve-2026-46434
vendors:
  - wger
products:
  - wger (<= 2.1)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: The UserDeactivateView grants access to anyone holding any one of gym.manage_gym, gym.manage_gyms, or gym.gym_trainer... and performs no privilege-hierarchy check.
    confidence_band: high
cves:
  - id: CVE-2026-46434
    cvss: 7.1
references:
  - https://github.com/advisories/GHSA-x249-cx55-2h87
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade wger to 2.6 or later
      owner: IT Operations
      due: 48h
      evidence: Source advisory recommends fixing the missing hierarchy check
  hunt_leads:
    - lead: Identify accounts with 'gym_trainer' role performing actions on 'gym_manager' accounts
      technique_id: T1068
      data_needed:
        - Web server logs or application access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source identifies GET /en/user/<manager_user_id>/deactivate as the attack vector
  mitigation_plan:
    - priority: immediate
      action: Patch wger to 2.6 or later
      owner: IT Operations
      addresses: CVE-2026-46434
      evidence: Source provided specific logic for the privilege hierarchy check fix
---

The wger workout manager (version 2.1 and earlier) contains an improper privilege management vulnerability (CVE-2026-46434) that allows a user with 'gym_trainer' permissions to deactivate accounts belonging to 'gym_manager' or 'general_gym_manager' roles within the same gym. The vulnerability exists because the `UserDeactivateView` and `UserActivateView` classes perform authorization using OR logic, which grants access if the requester possesses any of the permitted roles. Crucially, the application fails to verify whether the target user possesses a higher privilege level than the requester. Consequently, a malicious trainer can effectively lock out all gym managers, causing a denial of service for administrative operations. The issue is compounded by the fact that the 'trainer' role is always assignable by managers, allowing for the creation of accounts that can later be used to sabotage management access.

## Attack Chain

1. Attacker obtains or creates a user account assigned to the 'gym_trainer' group within a target gym.
2. Attacker logs into the wger platform using the trainer credentials.
3. Attacker identifies the user ID for a 'gym_manager' or 'general_gym_manager' account operating within the same gym instance.
4. Attacker constructs a malicious request to the `UserDeactivateView` endpoint, specifically `GET /en/user/<manager_user_id>/deactivate`.
5. The application validates the requester's 'gym_trainer' permission as sufficient for access to the view.
6. The `dispatch()` method confirms the trainer and the target manager belong to the same gym.
7. The application executes the deactivation logic without verifying if the target has higher privileges.
8. The victim manager account is set to `is_active = False`, resulting in immediate lockout.

## Impact

Successful exploitation results in a persistent denial of service for administrative users. Managers are unable to log in, manage gym members, or perform administrative tasks until manual intervention by a 'general_gym_manager' or superuser occurs. This directly impacts the integrity and availability of gym management operations.

## Recommendation

1. Upgrade to a version of wger that includes the privilege hierarchy check in `UserDeactivateView` and `UserActivateView`.
2. Audit current gym user roles and remove unnecessary 'gym_trainer' permissions until the patch is applied.
3. Implement strict monitoring for access to `/deactivate` or `/activate` endpoints by users who do not possess 'gym_manager' permissions.
4. Ensure all Django superuser or 'general_gym_manager' accounts are protected with multi-factor authentication to prevent lockout by compromised lower-privileged accounts.
