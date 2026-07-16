---
title: Keycloak JWT Authorization Bypass via Disabled User Accounts (CVE-2026-1609)
slug: 2026-07-keycloak-jwt-bypass
description: A vulnerability exists in Keycloak when its JSON Web Token (JWT) authorization grant preview feature is enabled, allowing a remote attacker with low privileges to exploit CVE-2026-1609 by presenting a valid assertion token from an external identity provider to obtain a JWT for a user account that has been disabled, thereby bypassing access controls and gaining unauthorized access to sensitive resources.
date: "2026-07-16T01:17:52Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - identity-management
  - authorization-bypass
  - keycloak
  - jwt
  - access-control
vendors:
  - Red Hat
products:
  - Keycloak
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: A remote attacker with low privileges can exploit this improper access control vulnerability by presenting a valid assertion token from an external identity provider to obtain a JWT for a disabled user. This allows unauthorized access to sensitive resources.
    confidence_band: high
cves:
  - id: CVE-2026-1609
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-1609
---

A significant flaw, identified as CVE-2026-1609, has been discovered in Red Hat Keycloak, an open-source identity and access management solution. This vulnerability arises when Keycloak's experimental JSON Web Token (JWT) authorization grant preview feature is activated. Under these conditions, Keycloak fails to properly verify the status of user accounts that have been explicitly disabled. Consequently, a remote attacker possessing low-level privileges and a valid assertion token, obtained from an external identity provider, can leverage this bypass. By presenting this token, the attacker can acquire a legitimate JWT for a disabled user account, effectively circumventing intended access controls. This unauthorized JWT can then be used to gain access to sensitive resources that should otherwise be protected, posing a critical security risk to systems relying on Keycloak for authentication and authorization.

## Attack Chain

1. Attacker with low privileges identifies a Keycloak instance with the JWT authorization grant preview feature enabled.
2. The attacker acquires a valid assertion token from an external identity provider, corresponding to a user account that has been disabled within Keycloak.
3. The attacker sends a JWT authorization grant request to the vulnerable Keycloak instance, presenting the valid assertion token for the disabled user.
4. Keycloak, due to the flaw, processes the request and fails to adequately validate the disabled status of the user account.
5. Keycloak issues a JSON Web Token (JWT) for the disabled user, treating the account as active and authorized.
6. The attacker receives the valid JWT, which represents unauthorized access to the disabled user's identity.
7. The attacker uses this newly obtained JWT to authenticate and gain unauthorized access to sensitive resources protected by Keycloak.

## Impact

The successful exploitation of CVE-2026-1609 can lead to a complete bypass of access controls for disabled user accounts, resulting in unauthorized access to sensitive data and resources within an organization's ecosystem. Attackers could impersonate disabled users, potentially accessing or manipulating confidential information, critical applications, or internal systems, depending on the privileges previously associated with the compromised disabled account. While no specific victim counts or targeted sectors are mentioned, any organization utilizing vulnerable configurations of Keycloak is at risk of significant data breaches and compromise of their identity management infrastructure.

## Recommendation

* Review your Keycloak configuration immediately to determine if the JSON Web Token (JWT) authorization grant preview feature is enabled.
* Apply available patches or updates for CVE-2026-1609 from Red Hat Keycloak as soon as they are released to remediate the vulnerability.
* If immediate patching is not possible, disable the JWT authorization grant preview feature in Keycloak to mitigate the risk of CVE-2026-1609 exploitation.
* Enable comprehensive logging for Keycloak authentication and authorization events to detect unusual JWT issuance or access attempts for disabled accounts.
