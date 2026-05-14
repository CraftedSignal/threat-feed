---
title: Fleet Windows MDM Azure AD JWT Authentication Bypass Vulnerability
slug: 2026-05-fleet-jwt-bypass
description: A vulnerability in Fleet versions prior to 4.82.0 allows authentication tokens from any Azure AD tenant to be accepted, enabling unauthorized device enrollment and MDM API access due to improper JWT signature validation, tracked as CVE-2026-24899.
date: "2026-05-14T13:15:33Z"
type: threat
types:
  - threat
severities:
  - high
tags:
  - jwt
  - azuread
  - authentication
  - bypass
  - mdm
  - fleetdm
vendors:
  - Microsoft
  - FleetDM
products:
  - fleetdm/fleet/v4
  - Azure AD
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
references:
  - https://github.com/advisories/GHSA-ffg9-j72f-j6xm
  - CVE-2026-24899
iocs:
  - type: email
    value: security@fleetdm.com
ioc_counts:
  email: 1
rules:
  - title: Detect CVE-2026-24899 Attempt - Suspicious Fleet Enrollment
    description: Detects attempts to exploit CVE-2026-24899 by identifying Windows MDM enrollment requests to Fleet from unexpected Azure AD tenants.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1547.009
    data_sources:
      - webserver
  - title: Detect CVE-2026-24899 - Fleet API Access from Unrecognized Device
    description: Detects potential exploitation of CVE-2026-24899 by identifying API requests to Fleet originating from devices that are not recognized or enrolled in the expected Azure AD tenant.
    platform: sigma
    severity: low
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1547.009
    data_sources:
      - webserver
rules_count: 2
---

A critical vulnerability exists in Fleet versions prior to 4.82.0, specifically affecting the Windows MDM enrollment flow. This flaw stems from insufficient validation of JWT signatures during the Azure AD authentication process. Fleet's implementation utilizes Microsoft's multi-tenant JWKS endpoint for signature verification but neglects to enforce the `aud` (audience) and `iss` (issuer) claims within the JWT. This oversight permits the acceptance of authentication tokens originating from any Azure AD tenant, as long as they are signed by Microsoft and contain the expected scopes. Successful exploitation allows attackers to bypass intended authorization controls, enabling them to enroll unauthorized devices and interact with Fleet's MDM management APIs, potentially exposing enrollment secrets.

## Attack Chain

1.  Attacker gains access to any Azure AD tenant, potentially through compromised credentials or a rogue application registration.
2.  The attacker requests an Azure AD access token with the necessary scopes for Fleet MDM enrollment.
3.  The attacker initiates the Windows MDM enrollment process, presenting the crafted Azure AD access token to the Fleet MDM endpoint.
4.  Fleet validates the JWT signature against Microsoft's JWKS endpoint but skips validation of the `aud` and `iss` claims.
5.  The unauthorized access token is accepted by Fleet, granting the attacker the ability to enroll a device under a different Azure AD tenant.
6.  The attacker leverages enrolled devices to interact with Fleet's MDM management APIs.
7.  Sensitive enrollment secrets embedded in MDM command payloads are exposed to the attacker.
8.  The attacker uses exposed secrets for further unauthorized access or lateral movement within the environment.

## Impact

Successful exploitation of CVE-2026-24899 can lead to unauthorized device enrollment, potentially giving attackers control over managed Windows systems. Fleet may expose sensitive enrollment secrets, facilitating further unauthorized access. This vulnerability has the potential to affect any organization using Fleet with Windows MDM enabled, leading to data breaches and compromised systems.

## Recommendation

*   Immediately upgrade Fleet to version 4.82.0 or later to address the vulnerability (reference: Affected Packages).
*   As an immediate workaround, disable Windows MDM in Fleet if an upgrade is not possible (reference: Workarounds).
*   Monitor Fleet logs for suspicious device enrollment activities originating from unexpected Azure AD tenants (requires specific logging not detailed in source).
*   Investigate any unauthorized device enrollments identified within the Fleet management console (requires manual review).
