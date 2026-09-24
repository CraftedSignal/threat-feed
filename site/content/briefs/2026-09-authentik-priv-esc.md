---
title: Privilege Escalation in authentik via Groups API
slug: 2026-09-authentik-priv-esc
description: An improper access control vulnerability (CVE-2026-94609) in authentik allows users with delegated group management permissions to elevate their privileges to full administrator by adding themselves to superuser-flagged groups.
date: "2026-09-24T18:15:30Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:authentik:authentik:*:*:*:*:*:*:*:*
tags:
  - privilege-escalation
  - authentik
  - rbac
vendors:
  - authentik
products:
  - authentik (<= 2026.2.6)
  - authentik (<= 2026.5.6)
  - authentik (<= 2026.8.1)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: An account with only a routine, commonly-delegated permission could add itself or any other user directly into an existing group flagged is_superuser=True.
    confidence_band: high
cves:
  - id: CVE-2026-94609
    cvss: 8.8
  - id: CVE-2026-40172
    cvss: 8.1
    epss: 0.00535
references:
  - https://github.com/goauthentik/authentik/security/advisories/GHSA-h6c5-mpvq-j4jc
  - https://nvd.nist.gov/vuln/detail/CVE-2026-94609
rules:
  - title: Detect Unauthorized PATCH Requests to authentik Groups API
    description: Detects potential CVE-2026-94609 exploitation attempts by monitoring PATCH requests to the groups API where the target action involves user modification.
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
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade authentik to 2026.2.7, 2026.5.7, or 2026.8.2
      owner: IT Operations
      due: 24h
      evidence: Fixed in 2026.2.7, 2026.5.7, 2026.8.2
  mitigation_plan:
    - priority: immediate
      action: Revoke authentik_core.add_user_to_group from non-administrative roles
      owner: IT Operations
      addresses: CVE-2026-94609
      evidence: Official advisory workaround
---

authentik is affected by a high-severity privilege escalation vulnerability (CVE-2026-94609) due to improper access control in the Groups API. The vulnerability exists within the `GroupSerializer.validate_users()` method, which fails to verify if the requesting user possesses the necessary `authentik_core.enable_group_superuser` permission when modifying the membership of a group flagged with `is_superuser=True`. 

By design, authentik uses two distinct permissions: `authentik_core.add_user_to_group` for standard team roster management and `authentik_core.enable_group_superuser` for assigning superuser status. Because the validation logic only checks for the presence of the routine management permission, an attacker holding a delegated "helpdesk" or "user manager" role can inject themselves or other users into existing superuser groups. This effectively bypasses the intended RBAC controls, leading to full instance compromise. This flaw is a symmetric counterpart to a previously fixed vulnerability (CVE-2026-40172). Affected versions include releases within the 2026.2, 2026.5, and 2026.8 branches.

## Attack Chain

1. Attacker obtains a low-privileged API token or session belonging to an account with `authentik_core.add_user_to_group` permissions.
2. Attacker interacts with the `/api/v3/core/groups/` endpoint to list available groups within the authentik instance.
3. Attacker identifies a target group that has the `is_superuser=True` attribute.
4. Attacker performs a `PATCH` request to `/api/v3/core/groups/{group_uuid}/` containing the target group UUID.
5. The `GroupSerializer.validate_users()` method processes the request, verifying only the routine `add_user_to_group` permission.
6. The system authorizes the injection of the attacker-controlled user ID into the superuser group's membership list.
7. The target user is instantly granted full administrative superuser privileges within the authentik environment.
8. Attacker leverages full administrative access to manage SSO configurations, user accounts, and secret storage.

## Impact

Successful exploitation allows a low-privileged user to gain full administrative control over the authentik instance. This facilitates unauthorized access to every tenant, interception of SSO authentication flows for downstream applications, modification of user accounts, and exfiltration or destruction of sensitive secrets and certificates managed by the instance.

## Recommendation

Prioritize the immediate patching of all authentik instances to the fixed versions (2026.2.7, 2026.5.7, or 2026.8.2). If immediate patching is not possible, organizations must strictly audit and restrict the `authentik_core.add_user_to_group` permission, ensuring it is revoked from all non-administrative roles. Detection teams should monitor for unauthorized `PATCH` requests targeting group membership, particularly where the initiator lacks administrative status.
