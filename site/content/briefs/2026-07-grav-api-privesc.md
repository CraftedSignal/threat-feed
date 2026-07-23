---
title: Grav API Plugin Privilege Escalation via Invitation Group Manipulation (CVE-2026-65897)
slug: 2026-07-grav-api-privesc
description: An authenticated attacker can exploit CVE-2026-65897 in Grav API Plugin versions prior to 1.0.10 by manipulating the 'groups' field during invitation creation, allowing invited accounts to gain super-admin API access, leading to privilege escalation.
date: "2026-07-23T12:24:23Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - privilege-escalation
  - vulnerability
vendors:
  - Grav
products:
  - Grav API Plugin
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1098
    technique_name: Account Manipulation
    evidence: Attackers can create invitation records with elevated group membership, and when accepted, the new account gains full super-admin API access without the inviter holding those permissions.
    confidence_band: high
cves:
  - id: CVE-2026-65897
    cvss: 8.8
references:
  - https://github.com/getgrav/grav/commit/345e79e3abf8c15f80e612a09f6643300071324b
  - https://github.com/getgrav/grav/commit/f9438d4e71389b1041ac60b69b0b5714ecfa3bdd
  - https://github.com/getgrav/grav/security/advisories/GHSA-m86m-jjcg-gcvv
  - https://www.vulncheck.com/advisories/grav-api-plugin-privilege-escalation-via-invitations-groups
iocs:
  - type: url
    value: https://github.com/getgrav/grav/commit/345e79e3abf8c15f80e612a09f6643300071324b
  - type: url
    value: https://github.com/getgrav/grav/commit/f9438d4e71389b1041ac60b69b0b5714ecfa3bdd
  - type: url
    value: https://github.com/getgrav/grav/security/advisories/GHSA-m86m-jjcg-gcvv
  - type: url
    value: https://www.vulncheck.com/advisories/grav-api-plugin-privilege-escalation-via-invitations-groups
ioc_counts:
  url: 4
---

CVE-2026-65897 describes a critical privilege escalation vulnerability affecting Grav API Plugin versions prior to 1.0.10. An authenticated attacker possessing `api.users.write` permissions can exploit this flaw by crafting an invitation request to the `InvitationsController::create()` function. The vulnerability stems from insufficient validation of the `groups` field within this request, enabling the attacker to assign elevated `api.super` permissions to the invited account. Once the invitation is accepted by the target, the newly created user account inherits full super-admin API access, even if the inviter themselves does not possess such high-level privileges. This bypasses intended access controls and can lead to complete compromise of the Grav instance's API functionality. The vulnerability is rated with a CVSS v3.1 base score of 8.8 (High).

## Attack Chain

1. An attacker obtains authenticated access to a Grav instance with `api.users.write` permissions.
2. The attacker initiates an invitation process by calling the `InvitationsController::create()` function via the Grav API.
3. Within the API request, the attacker manipulates the `groups` field to include groups that are typically reserved for super-admin accounts (e.g., those granting `api.super` permissions).
4. The Grav API Plugin, due to the vulnerability, fails to properly validate whether the inviting user has the authority to assign these elevated group memberships.
5. An invitation is generated and sent to the target user with the maliciously crafted, elevated group assignments embedded.
6. The target user accepts the invitation and creates their account.
7. Upon acceptance, the newly created account is automatically assigned to the super-admin groups specified by the attacker, granting full super-admin API access.
8. The attacker has successfully escalated privileges, gaining unauthorized super-admin API capabilities through the newly created account.

## Impact

Successful exploitation of CVE-2026-65897 results in severe privilege escalation, allowing an authenticated attacker with limited user write permissions to create new accounts with full super-admin API access. This grants the attacker comprehensive control over the Grav instance through its API, potentially leading to data manipulation, unauthorized data access, complete system takeover, or disruption of services. Organizations using affected Grav API Plugin versions face a high risk of compromise, as an attacker could gain control over the content, users, and settings of their Grav installation without the initial compromise of an existing super-admin account. The CVSS v3.1 base score of 8.8 reflects this critical impact.

## Recommendation

* Patch CVE-2026-65897 immediately by updating the Grav API Plugin to version 1.0.10 or later as detailed in the references.
* Review Grav API Plugin installations for any signs of suspicious user invitations or recently created accounts with unexpected `api.super` permissions, especially those created by non-super-admin users.
* Refer to the provided references for official advisories and patch information for CVE-2026-65897.
