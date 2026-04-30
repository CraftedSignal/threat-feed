---
title: wger Broken Access Control in Global Gym Configuration Update Endpoint
slug: 2024-01-09-wger-privesc
description: The wger application has a broken access control vulnerability in the global gym configuration update endpoint, allowing low-privileged authenticated users to modify installation-wide configuration settings and escalate privileges.
date: "2026-04-16T01:35:16Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - privilege-escalation
  - broken-access-control
  - web-application
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-xppv-4jrx-qf8m
rules:
  - title: wger GymConfig Update by Low-Privilege User
    description: Detects unauthorized modification of the GymConfig object by low-privileged users in wger via the /config/gym-config/edit endpoint.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: wger Default Gym Modified
    description: Detects modification of the default gym value.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The wger application exposes a global configuration edit endpoint at `/config/gym-config/edit` that is vulnerable to broken access control. The vulnerability exists because the `GymConfigUpdateView` uses the wrong mixin (`WgerFormMixin` instead of `WgerPermissionMixin`), preventing proper enforcement of the `config.change_gymconfig` permission. This allows a low-privileged authenticated user to modify the global `GymConfig` singleton (pk=1), triggering server-side side effects via the `GymConfig.save()` method. This vertical privilege escalation allows unauthorized modification of installation-wide state and bulk updates to other users’ records, violating the intended administrative trust boundary. The vulnerability affects wger versions 2.1 and earlier.

## Attack Chain

1.  An attacker authenticates to the wger application with a low-privileged user account.
2.  The attacker navigates to the global configuration edit endpoint at `/config/gym-config/edit`.
3.  The server processes the request via the `GymConfigUpdateView` which inherits from `WgerFormMixin`.
4.  `WgerFormMixin` attempts to perform ownership checks but fails because `GymConfig` does not implement `get_owner_object()`.
5.  The application allows the attacker to modify the `default_gym` setting.
6.  The attacker submits the form with a modified `default_gym` value.
7.  The `GymConfig.save()` method is called, updating `UserProfile` records with a gym set to null.
8.  The attacker has successfully modified installation-wide configuration, potentially bulk-updating user records and violating administrative trust boundaries.

## Impact

Successful exploitation of this vulnerability allows a low-privileged user to escalate privileges and modify global configuration settings. This could lead to unauthorized modification of user profiles and tenant assignments, affecting new registrations and existing users lacking a gym. On deployments with multiple gyms, this vulnerability can result in widespread data manipulation and a violation of the intended administrative trust boundary. The vulnerability affects wger deployments, impacting organizations that rely on the application for managing fitness and exercise data.

## Recommendation

*   Apply the recommended fix by ensuring permission enforcement runs before the form dispatch. Implement the suggested code change in `wger/config/views/gym_config.py` using the project mixin by updating the inheritance order: `class GymConfigUpdateView(WgerPermissionMixin, WgerFormMixin, UpdateView):` as described in the advisory.
*   Deploy the Sigma rule "wger GymConfig Update by Low-Privilege User" to detect unauthorized modification of the GymConfig object via the `/config/gym-config/edit` endpoint.
*   Monitor web server logs for POST requests to the `/config/gym-config/edit` endpoint originating from low-privileged user accounts, using the URL as an indicator.
