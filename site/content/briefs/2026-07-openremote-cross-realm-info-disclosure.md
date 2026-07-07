---
title: OpenRemote Cross-Realm User Information Disclosure (CVE-2026-54641)
slug: 2026-07-openremote-cross-realm-info-disclosure
description: A high-severity vulnerability (CVE-2026-54641) in OpenRemote's `UserResourceImpl.java` allows a realm administrator in a multi-tenant deployment to perform cross-realm user enumeration and privilege-level reconnaissance by reading sensitive user information (profile, client roles, and realm roles) from any other realm, including the master realm, due to missing authorization checks in specific REST API endpoints.
date: "2026-07-06T20:51:11Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - OpenRemote
  - Vulnerability
  - API
  - Information Disclosure
  - Access Control
  - Multi-tenant
vendors:
  - OpenRemote
products:
  - openremote-manager (< 1.24.2)
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1087
    technique_name: Account Discovery
    evidence: The vulnerability enables cross-tenant user enumeration and privilege-level reconnaissance. On a multi-tenant deployment the master realm administrator account is reachable from any tenant realm admin.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1069
    technique_name: Permission Groups Discovery
    evidence: A realm admin of tenant B can read the profile, client roles, and realm roles of any user in any other realm (including the master realm)... This exposes admin account identities and role assignments.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-xqr9-4wvv-gvch
rules:
  - title: Detect CVE-2026-54641 Exploitation - OpenRemote Cross-Realm User Info Disclosure
    description: Detects CVE-2026-54641 exploitation - HTTP GET requests targeting master realm user information endpoints from a non-master realm context, indicating cross-realm information disclosure attempts in OpenRemote.
    platform: sigma
    severity: high
    tactics:
      - collection
      - discovery
    techniques:
      - T1069
      - T1087
      - T1592
    data_sources:
      - webserver
rules_count: 1
---

A high-severity vulnerability, CVE-2026-54641, has been identified in OpenRemote's `openremote-manager` package, affecting versions prior to `1.24.2`. This flaw specifically resides in the `UserResourceImpl.java` file, where three read endpoints (`get`, `getUserClientRoles`, `getUserRealmRoles`) lack an authenticated-realm guard. This oversight allows a realm administrator from any non-master tenant to retrieve sensitive user profile data, client roles, and realm roles belonging to users in other realms, including the highly privileged master realm, simply by supplying the target user's UUID in the REST API path. This cross-tenant information disclosure facilitates user enumeration and privilege reconnaissance, providing attackers with valuable intelligence (usernames, email addresses, role assignments) that can be leveraged for further targeted attacks such as credential stuffing, social engineering, or privilege escalation within multi-tenant OpenRemote deployments.

## Attack Chain

1.  An attacker gains administrator-level access to a non-master OpenRemote tenant, possessing the `read:admin` role.
2.  The attacker performs reconnaissance to identify a target user's UUID within another realm, typically the privileged master realm, potentially through accessible audit logs, API responses, or provisioning records.
3.  The attacker authenticates to their controlled non-master tenant (e.g., `tenantb`) and obtains a valid OpenID Connect access token.
4.  The attacker crafts and sends an authenticated HTTP GET request to the vulnerable `/api/{caller_realm}/user/{target_realm}/{user_id}` endpoint, specifying the master realm as the target (`target_realm`) and the master admin's UUID.
5.  The attacker proceeds to send an authenticated HTTP GET request to the `/api/{caller_realm}/user/{target_realm}/userRealmRoles/{user_id}` endpoint to retrieve the target master realm user's assigned realm roles.
6.  Subsequently, the attacker sends an authenticated HTTP GET request to the `/api/{caller_realm}/user/{target_realm}/userRoles/{user_id}/{client_id}` endpoint to gather the target master realm user's client roles.
7.  Due to the absence of proper authorization checks in `UserResourceImpl.java`, the OpenRemote server inadvertently returns sensitive user profile, realm role, and client role information from the target master realm to the attacker, despite their non-master realm token.
8.  The attacker utilizes the disclosed user identities, privilege levels, and role assignments to plan and execute subsequent attacks, such as credential stuffing against identified administrator accounts, social engineering campaigns, or exploiting other vulnerabilities for privilege escalation.

## Impact

This vulnerability allows any realm administrator with `read:admin` permissions in a non-master tenant to enumerate user accounts, obtain email addresses, determine enabled/disabled status, and retrieve the full set of Keycloak roles for any user across all realms, including the most privileged master realm. This breaks tenant isolation in hosted or shared OpenRemote deployments, compromising the confidentiality of user data. The exposure of sensitive master administrator account identities and their extensive role assignments significantly aids in targeted attacks, making credential stuffing, social engineering, and potential privilege escalation much more feasible. Successful exploitation can lead to a complete compromise of the OpenRemote instance if master administrator credentials are subsequently brute-forced or phished.

## Recommendation

*   Immediately patch OpenRemote instances to version `1.24.2` or higher to remediate CVE-2026-54641.
*   Deploy the Sigma rule in this brief to your SIEM to detect suspicious cross-realm information disclosure attempts.
*   Monitor webserver logs for HTTP GET requests matching the patterns identified in the Sigma rule, specifically for access to `/api/{non_master_realm}/user/master/*` endpoints by non-master realm administrators.
