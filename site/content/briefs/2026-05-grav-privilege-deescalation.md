---
title: Grav CMS Privilege De-escalation via User Overwrite
slug: 2026-05-grav-privilege-deescalation
description: A low-privileged user with user creation permissions in Grav CMS can overwrite existing accounts, including the primary administrator, leading to a Denial of Service (DoS) and privilege de-escalation by exploiting a business logic vulnerability in versions prior to 2.0.0-beta.2.
date: "2026-05-06T14:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - privilege-escalation
  - denial-of-service
  - web-application
vendors:
  - Grav
products:
  - Grav
  - composer/getgrav/grav (< 2.0.0-beta.2)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1556
    technique_name: Modify Authentication Process
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://github.com/advisories/GHSA-rr73-568v-28f8
  - https://github.com/getgrav/grav/commit/d904efc33
  - https://github.com/getgrav/grav/commit/19c2f8da7
iocs:
  - type: url
    value: https://github.com/user-attachments/assets/047cb44e-0279-402b-b4fb-12bf5d427a5e
ioc_counts:
  url: 1
rules:
  - title: Grav CMS User Overwrite Attempt
    description: Detects attempts to create a user with the same username as an existing administrator account in Grav CMS, potentially leading to privilege de-escalation.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1556.001
    data_sources:
      - webserver
      - linux
  - title: Grav CMS POST Request to User Management
    description: Detects POST requests to the user management endpoint which could indicate malicious user creation/modification attempts.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1556.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Grav CMS versions prior to 2.0.0-beta.2 are vulnerable to a privilege de-escalation attack. A low-privileged user with the `admin.users.create` permission can overwrite the primary administrator account by creating a new user with the same username. Due to an insecure "Create or Update" logic, the system updates the existing account's metadata and permissions instead of rejecting the request. Although the attacker cannot directly elevate their own privileges, they can effectively disable administrative accounts, leading to a complete loss of management control over the CMS. This vulnerability was addressed in Grav core on April 24, 2026, with commit d904efc33.

## Attack Chain

1. An administrator creates a low-privileged user (e.g., adminuser) and grants them the `admin.users.create` permission.
2. The low-privileged user logs into the Grav Admin Panel.
3. The user navigates to the user creation page.
4. The user fills out the "Add User" form, using the username of an existing administrator account (e.g., root0).
5. The user submits the form, which triggers the vulnerable `UserObject::save` function.
6. The system overwrites the administrator account's configuration file (e.g., user/accounts/root0.yaml) with the provided details, effectively stripping the administrator's permissions.
7. The administrator attempts to log in, but their account now has reduced or no administrative privileges.
8. The attacker has effectively achieved privilege de-escalation, causing a denial of service for the administrator.

## Impact

Successful exploitation of this vulnerability allows a low-privileged user to disable all administrative accounts in the Grav CMS. This leads to a complete loss of management control over the CMS, potentially impacting any Grav installation where non-admin users are granted permission to create other users. The vulnerability has been assigned CVE-2026-42609 with a severity rating of High.

## Recommendation

*   Upgrade Grav CMS to version 2.0.0-beta.2 or later to address the vulnerability described in this brief.
*   Review user permissions and restrict `admin.users.create` permissions to trusted users only, particularly in versions prior to 2.0.0-beta.2.
*   Monitor webserver logs for unusual user creation requests, specifically attempts to create users with existing administrator usernames using the Sigma rule provided below.
*   Audit user accounts regularly to detect any unauthorized changes in permissions.
