---
brief_id: brief-2026-10-22-keycloak-privilege-escalation
event_id: brief-2026-10-22-keycloak-privilege-escalation
revision: 1
activity_at: "2026-10-22T11:47:21Z"
title: 'Keycloak: Privilege escalation in admin REST API (CVE-2026-94000)'
slug: 2026-10-keycloak-privilege-escalation
description: Keycloak versions up to 26.8.1 are vulnerable to privilege escalation where a user with "manage-users" permissions can assign composite roles containing "realm-admin" privileges due to incomplete authorization checks.
date: "2026-10-22T11:47:21Z"
type: threat
types:
  - threat
severities:
  - low
actors:
  - SecFathy
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: very likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:keycloak:keycloak:*:*:*:*:*:*:*:*
tags:
  - privilege-escalation
  - keycloak
  - authentication-bypass
vendors:
  - Keycloak
products:
  - Keycloak (<= 26.8.1)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Privilege escalation in Keycloak admin REST API allows manage-users to gain realm-admin.
    confidence_band: high
cves:
  - id: CVE-2026-94000
    cvss: 6.6
    epss: 0.00401
    kev_status: "false"
references:
  - https://sploitus.com/exploit?id=B585227F-9AEE-5854-B896-D4F313104ED4
  - https://sploitus.com/exploit?id=B585227F-9AEE-5854-B896-D4F313104ED4&utm_source=rss&utm_medium=rss
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade all Keycloak instances to a version containing the fix for CVE-2026-94000.
      owner: IT Operations
      due: 72h
      evidence: Source document identifies the vulnerability exists in 26.8.1.
  hunt_leads:
    - lead: Search API access logs for POST requests to role mapping endpoints originated by users with 'manage-users' role.
      technique_id: T1068
      data_needed:
        - Keycloak access logs (REST API calls)
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Source identifies RoleMapperResource and ClientRoleMappingsResource as the target endpoints.
---

Keycloak up to version 26.8.1 contains a privilege escalation vulnerability (CVE-2026-94000) within its admin REST API. While Keycloak previously hardened "group join" operations to check for nested admin roles, the role-mapping endpoints (`RoleMapperResource.addRealmRoleMappings` and `ClientRoleMappingsResource.addClientRoleMapping`) do not recursively walk the children of a composite role. Consequently, an attacker holding only the `manage-users` role can map a composite role that transitively grants `realm-management/realm-admin` privileges, effectively escalating their own account or other users/groups to `realm-admin`.

## Attack Chain
1. Attacker obtains valid credentials for a Keycloak account assigned the `manage-users` role.
2. Attacker enumerates available roles via the `.../role-mappings/.../available` endpoint, which is accessible to `manage-users` users.
3. Attacker identifies a composite role (or creates one if existing roles permit) that wraps `realm-management/realm-admin` as a child.
4. Attacker performs a `POST` request to `addRealmRoleMappings` or `addClientRoleMapping` to assign this composite role to a target user, group, or client.
5. The Keycloak server fails to recursively inspect the nested children of the role and validates only the top-level role name.
6. The target user, group, or client gains effective `realm-admin` permissions, allowing for further malicious activity such as creating new roles or accessing confidential information.

## Impact
Successful exploitation allows a user with restricted `manage-users` privileges to gain full `realm-admin` access. This facilitates complete control over the realm, including user management, configuration of clients, and access to sensitive information, effectively bypassing the principle of least privilege.

## Recommendation
- Update all Keycloak instances to a version where CVE-2026-94000 is patched.
- Implement a policy to restrict the ability of `manage-users` to perform role-mapping operations if not strictly required for business operations.
- Audit existing role-mapping assignments for composite roles that may grant elevated administrative permissions to unauthorized users.
- Monitor logs for unusual `POST` requests to role mapping endpoints by users holding the `manage-users` role.
