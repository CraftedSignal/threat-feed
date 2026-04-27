---
title: OpenRemote Improper Access Control Leads to Privilege Escalation
slug: 2024-01-02-openremote-privesc
description: OpenRemote is vulnerable to privilege escalation, allowing an attacker with write:admin privileges in one Keycloak realm to gain administrator access to the master realm by manipulating Keycloak realm roles due to missing authorization checks in the updateUserRealmRoles function.
date: "2024-01-02T12:00:00Z"
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

OpenRemote, a digital twin platform, is susceptible to a privilege escalation vulnerability (CVE-2026-41166) affecting versions prior to 1.22.1 of the openremote-manager component. An attacker possessing `write:admin` privileges in any Keycloak realm can exploit this flaw to escalate privileges to the `master` realm. This is achieved by calling the Manager API's `updateUserRealmRoles` function to modify Keycloak realm roles for users in other realms, including the `master` realm. The…
