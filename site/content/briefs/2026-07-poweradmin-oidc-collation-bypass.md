---
title: Poweradmin OIDC `sub` Collation Bypass Leads to Account Takeover
slug: 2026-07-poweradmin-oidc-collation-bypass
description: A collation vulnerability in Poweradmin's OIDC integration allows an unauthenticated attacker to take over victim accounts by exploiting the case and accent-insensitive MySQL collation (`utf8mb4_unicode_ci`) used for OIDC subject (`sub`) identifiers, causing the attacker's colliding `sub` to resolve to the victim's `user_id` during authentication.
date: "2026-07-24T22:02:03Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - account-takeover
  - oidc
  - vulnerability
  - web-application
  - poweradmin
vendors:
  - Poweradmin
products:
  - Poweradmin >= 4.1.0, < 4.2.5
  - Poweradmin >= 4.3.0, < 4.3.4
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: An attacker who can register or control an OIDC principal with an accent/collation variant of a victim's OIDC subject can authenticate with the attacker's own IdP credentials and obtain a Poweradmin session for the victim's local account.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-cmwh-g2h8-c222
---

A high-severity vulnerability has been identified in Poweradmin, an open-source web-based management tool for PowerDNS. This flaw, tracked in GHSA-cmwh-g2h8-c222, allows an unauthenticated attacker to bypass OIDC identity collation, leading to account takeover. The issue stems from Poweradmin's use of a case- and accent-insensitive MySQL collation (`utf8mb4_unicode_ci`) for storing and matching OIDC subject identifiers (`oidc_subject`). An attacker can create an OIDC account with a subject that is a collation variant of a legitimate victim's subject (e.g., `victim-login` vs. `victím-login`). When the attacker attempts to authenticate, Poweradmin's database lookup, performed under the weak collation, incorrectly matches the attacker's subject to the victim's existing `user_id`, granting the attacker an authenticated session to the victim's Poweradmin account. The vulnerability affects Poweradmin versions 4.1.0 through 4.2.4 and 4.3.0 through 4.3.3, and it has been fixed in versions 4.2.5, 4.3.4, and 4.4.0.

## Attack Chain

1. A legitimate victim links their OIDC account with Poweradmin; Poweradmin stores the victim's OIDC `sub` (e.g., `victim-login`) in the `oidc_user_links` table with a `utf8mb4_unicode_ci` collation.
2. An attacker creates an OIDC account at the same OIDC provider with a `sub` identifier that is a collation variant of the victim's `sub` (e.g., `victím-login`), exploiting the accent-insensitive nature of the collation.
3. The attacker initiates an OIDC login to Poweradmin by accessing `/oidc/login?provider=generic` and authenticates with their attacker OIDC credentials (`victím-login`).
4. Poweradmin receives the attacker's OIDC `sub` (`victím-login`) from the OIDC provider's userinfo endpoint after a successful authorization code flow.
5. Poweradmin queries its `oidc_user_links` database table to find an existing user linked to the received `oidc_subject` and `provider_id`.
6. Due to the `utf8mb4_unicode_ci` collation used for `oidc_subject`, the database query interprets the attacker's `sub` (`victím-login`) as equal to the victim's `sub` (`victim-login`).
7. The database returns the `user_id` associated with the victim's account, and Poweradmin establishes an authenticated session for the attacker under the victim's identity, leading to account takeover.

## Impact

Successful exploitation of this vulnerability allows an unauthenticated attacker, with control over an OIDC account that has a colliding subject identifier, to gain full access to a victim's Poweradmin account. This can result in unauthorized modification or deletion of DNS records, compromise of administrative settings, and complete control over the PowerDNS environment managed by Poweradmin. The attacker can achieve this without knowing or modifying the victim's password, leveraging only their own OIDC credentials and the database collation weakness. No specific victim counts or targeted sectors were provided, but any organization using affected Poweradmin versions with OIDC authentication is at risk.

## Recommendation

* Patch Poweradmin installations to versions 4.2.5, 4.3.4, or 4.4.0 immediately to address the OIDC `sub` collation bypass vulnerability.
* As part of the upgrade process, execute the provided SQL update script located in the `sql/` directory for your specific database to migrate the `oidc_user_links` table columns (`oidc_subject`, `provider_id`) to a binary or byte-preserving collation (e.g., `utf8mb4_bin`).
* Review other identity and authorization lookups within your Poweradmin environment, specifically `findUserByEmail()`, `findPermissionTemplateByName()`, and `findGroupByName()`, to ensure they enforce byte-exact matching where security boundaries are involved.
