---
title: Avo Framework Broken Access Control Vulnerability
slug: 2024-01-03-avo-broken-access-control
description: Avo framework version 3.x contains a critical Broken Access Control vulnerability in the ActionsController. Due to insecure action lookup logic, an authenticated user can execute any Action class on any resource, even if the action is not registered for that specific resource. This leads to Privilege Escalation and unauthorized data manipulation across the entire application. Version 3.31.2 remediates this issue.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - broken-access-control
  - privilege-escalation
  - ruby
vendors:
  - rubygems
products:
  - avo
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-qc5p-3mg5-9fh8
rules:
  - title: Detect Avo Unauthorized Action Execution
    description: Detects attempts to execute Avo actions on resources where they are not explicitly registered, indicating a potential broken access control exploit.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect Avo Sensitive Action Class Use
    description: Detects the use of sensitive action classes, like ToggleAdmin. This might be related to unauthorized actions.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A critical broken access control vulnerability exists within the Avo framework, specifically affecting version 3.x. This vulnerability resides in the `ActionsController` and stems from an insecure action lookup mechanism. An authenticated user, regardless of their privilege level, can execute any Action class (descendants of `Avo::BaseAction`) on any resource within the application. This occurs because the system fails to validate whether the requested action is legitimately registered or permitted for the resource context specified in the request. The absence of this verification allows for the circumvention of intended resource-action mappings. Successful exploitation leads to privilege escalation, unauthorized data manipulation, and potential compromise of the application's integrity. It is recommended to upgrade to version 3.31.2 or later, which addresses this vulnerability.

## Attack Chain

1. An attacker authenticates to the Avo admin panel with low-level privileges.
2. The attacker identifies a sensitive action class, such as `Avo::Actions::ToggleAdmin`.
3. The attacker identifies a target record ID, such as a user ID they wish to manipulate.
4. The attacker crafts a POST request to a resource endpoint where the target action is NOT registered (e.g., `/admin/resources/posts/actions`).
5. The POST request includes a payload containing the `action_id` parameter set to the sensitive action class (`Avo::Actions::ToggleAdmin`).
6. The POST request also includes a `fields[avo_resource_ids]` parameter set to the target record ID.
7. Due to the insecure action lookup in `Avo::ActionsController`, the server executes the `ToggleAdmin` action on the specified user ID.
8. The attacker's privileges are escalated, or unauthorized data manipulation occurs due to the successful execution of the unintended action.

## Impact

The exploitation of this broken access control vulnerability can have severe consequences. A successful attack can lead to privilege escalation, allowing attackers to gain administrative control over the application. Unauthorized operations can be performed, leading to data breaches or data manipulation. Sensitive actions designed for restricted resources can be triggered against any record ID, potentially compromising the integrity and confidentiality of data. The impact includes unauthorized deletion, archival, or updates to records, causing reputational damage and potential financial losses.

## Recommendation

*   Upgrade to Avo version 3.31.2 or later, which contains the necessary fix to restrict action lookup to registered actions for the current resource context.
*   Deploy the Sigma rule `Detect Avo Unauthorized Action Execution` to monitor for attempts to execute actions on resources where they are not registered.
*   Review and audit existing Avo action registrations to ensure that actions are appropriately mapped to resources within the application.
