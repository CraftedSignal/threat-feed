---
title: wger Cross-Tenant Password Reset and Plaintext Disclosure Vulnerability
slug: 2026-05-wger-password-reset
description: A vulnerability in wger version 2.5 and earlier allows an attacker with `gym.manage_gym` permission and `gym=None` to reset the password of any other `gym=None` user, disclosing the new password in plaintext and allowing account takeover.
date: "2026-05-07T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - vulnerability
  - account-takeover
  - web-application
vendors:
  - wger
products:
  - wger (<= 2.5)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
references:
  - https://github.com/advisories/GHSA-mhc8-p3jx-84mm
rules:
  - title: Detect Wger Password Reset Request
    description: Detects requests to the vulnerable password reset endpoint in wger.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1078
    data_sources:
      - webserver
      - linux
  - title: Detect Wger Password Disclosure in HTTP Response
    description: Detects plaintext password disclosure in the HTTP response body from the vulnerable wger password reset endpoint.
    platform: sigma
    severity: critical
    tactics:
      - credential_access
      - initial_access
    techniques:
      - T1078
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A critical vulnerability exists in wger version 2.5 and earlier that allows cross-tenant password resets and plaintext disclosure. The vulnerability is located in the `reset_user_password` and `gym_permissions_user_edit` views, where an authorization check using Python object comparison (`!=`) is bypassed when both the attacker and victim have no gym assignment (`gym=None`). This enables a user with `gym.manage_gym` permission and `gym=None` to reset the password of any other `gym=None` user. The new password is then returned verbatim in the HTML response body, leading to one-shot full account takeover. This is especially impactful as the `gym=None` state is the default for newly registered users. The vulnerability was tested on `wger/server:latest` Docker image, running Django 5.2.13.

## Attack Chain

1. The attacker authenticates to the wger instance with a user account that has `gym.manage_gym` permission but is not associated with a gym (`gym=None`).
2. The attacker crafts a `GET` request to the `/en/gym/user/<user_pk>/reset-user-password` endpoint, where `<user_pk>` is the user ID of the target user who also has `gym=None`.
3. The vulnerable code at `wger/gym/views/user.py` compares the attacker's `userprofile.gym` to the target user's `userprofile.gym` using `!=`. Since both are `None`, the comparison evaluates to `False`, bypassing the intended authorization check.
4. The server generates a new random password for the target user using the `password_generator()` function.
5. The server updates the target user's password in the database using `user.set_password(password)` and `user.save()`.
6. The server renders the new plaintext password in the HTTP response body within the `user/trainer_login.html` template.
7. The attacker extracts the plaintext password from the HTTP response.
8. The attacker uses the extracted plaintext password to authenticate as the target user, achieving full account takeover and invalidating the victim's original password.

## Impact

Successful exploitation of this vulnerability allows an attacker with `gym.manage_gym` permissions, but no gym assignment, to reset the passwords of other unassigned users, gaining full access to their accounts. This leads to complete confidentiality, integrity, and availability loss for all unaffiliated accounts. Every wger instance with public registration is affected due to the default `gym=None` state for new users. An attacker could leverage this to access sensitive user data, modify account settings, or perform other actions as the compromised user.

## Recommendation

*   Apply the patch suggested in the advisory to `wger/gym/views/user.py`, using the `_id` suffix to access the raw integer foreign key (`trainer_gym_id = request.user.userprofile.gym_id`) and explicitly check for `None` (`if trainer_gym_id is None or trainer_gym_id != member_gym_id:`).
*   Implement the `same_gym()` helper pattern across all five affected views: `reset_user_password`, `gym_permissions_user_edit`, `admin_notes_list`, `documents_list`, and `contracts_list`.
*   Deploy the Sigma rule "Detect Wger Password Reset Request" to identify attempts to exploit this vulnerability by monitoring HTTP requests to the `/en/gym/user/<user_pk>/reset-user-password` endpoint.
*   Monitor web server logs for HTTP 200 responses to `/en/gym/user/<user_pk>/reset-user-password` that contain the string `<tr><th>Password</th><td>` in the response body, indicating potential plaintext password disclosure.
*   Upgrade wger installations to a patched version beyond 2.5 to remediate CVE-2026-43948.
