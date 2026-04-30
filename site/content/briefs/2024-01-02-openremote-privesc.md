---
title: OpenRemote Improper Access Control Leads to Privilege Escalation
slug: 2024-01-02-openremote-privesc
description: OpenRemote is vulnerable to privilege escalation, allowing an attacker with write:admin privileges in one Keycloak realm to gain administrator access to the master realm by manipulating Keycloak realm roles due to missing authorization checks in the updateUserRealmRoles function.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - privilege-escalation
  - access-control
  - openremote
vendors:
  - OpenRemote
products:
  - openremote-manager
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-49vv-25qx-mg44
rules:
  - title: Detect OpenRemote UserRealmRoles API Abuse
    description: Detects suspicious calls to the updateUserRealmRoles API endpoint targeting different realms, indicating potential privilege escalation attempts in OpenRemote.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect OpenRemote updateUserRealmRoles Request with Admin Role
    description: Detects PUT requests to the OpenRemote updateUserRealmRoles endpoint attempting to assign the 'admin' role, indicating potential privilege escalation.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

OpenRemote, a digital twin platform, is susceptible to a privilege escalation vulnerability (CVE-2026-41166) affecting versions prior to 1.22.1 of the openremote-manager component. An attacker possessing `write:admin` privileges in any Keycloak realm can exploit this flaw to escalate privileges to the `master` realm. This is achieved by calling the Manager API's `updateUserRealmRoles` function to modify Keycloak realm roles for users in other realms, including the `master` realm. The vulnerability lies in the absence of authorization checks within the `UserResourceImpl.java` file, which fails to validate if the caller has administrative rights over the realm they are attempting to modify. This oversight allows an attacker to grant themselves or another user administrative privileges on the master realm, leading to full Keycloak administrator access.

## Attack Chain

1. The attacker gains initial access to a Keycloak realm and obtains `write:admin` privileges for the OpenRemote client within that realm.
2. The attacker identifies a low-privilege user in the `master` Keycloak realm and retrieves their UUID.
3. The attacker authenticates as the user from their controlled realm to obtain a valid Bearer access token.
4. The attacker crafts a malicious API request targeting the vulnerable `updateUserRealmRoles` endpoint, specifying the `master` realm and the UUID of the target user.
5. The attacker sets the "roles" parameter in the request body to include the "admin" role, effectively granting the target user Keycloak administrator privileges in the master realm.
6. The attacker sends the crafted API request to the OpenRemote Manager API, bypassing the missing authorization check.
7. The OpenRemote application processes the request and updates the target user's realm roles in the `master` Keycloak realm.
8. The attacker verifies the successful privilege escalation by confirming that the target user in the `master` realm now possesses the "admin" role via the Keycloak Admin Console, thus gaining full control over the master realm.

## Impact

Successful exploitation of this vulnerability allows an attacker to gain complete control over the `master` Keycloak realm within OpenRemote. This grants the attacker the ability to manage all users, roles, and clients within the `master` realm, potentially leading to unauthorized access to sensitive data, disruption of services, and further lateral movement within the OpenRemote environment. Given that the `master` realm is typically used for managing the entire OpenRemote instance, the impact is critical.

## Recommendation

*   Upgrade to OpenRemote version 1.22.1 or later to patch CVE-2026-41166, addressing the improper access control in the `updateUserRealmRoles` function.
*   Implement additional authorization checks within the `UserResourceImpl.java` file to validate that the caller has administrative rights over the target realm before allowing modifications to user realm roles.
*   Deploy the provided Sigma rule `Detect OpenRemote UserRealmRoles API Abuse` to monitor for suspicious calls to the updateUserRealmRoles API endpoint targeting different realms.
