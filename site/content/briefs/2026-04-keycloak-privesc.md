---
title: Keycloak Authorization Code Forging Vulnerability (CVE-2026-4282)
slug: 2026-04-keycloak-privesc
description: An unauthenticated attacker can exploit CVE-2026-4282 in Keycloak's SingleUseObjectProvider to forge authorization codes, leading to privilege escalation and the creation of admin-capable access tokens.
date: "2026-04-02T13:16:26Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - keycloak
  - privilege-escalation
  - authorization
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
cves:
  - id: CVE-2026-4282
    cvss: 7.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4282
  - https://access.redhat.com/security/cve/CVE-2026-4282
  - https://bugzilla.redhat.com/show_bug.cgi?id=2448061
rules:
  - title: Detect Suspicious Keycloak Admin Token Creation
    description: Detects the creation of admin-capable access tokens after potential authorization code forging in Keycloak.
    platform: sigma
    severity: critical
    tactics:
      - privilege_escalation
    techniques:
      - T1548
    data_sources:
      - webserver
      - linux
  - title: Detect Keycloak Authorization Endpoint Access with Suspicious Parameters
    description: Detects access to the Keycloak authorization endpoint with unusual or suspicious parameters, potentially indicating an attempt to exploit CVE-2026-4282.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1588.006
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2026-4282 identifies a critical vulnerability within the Keycloak authentication server, specifically affecting the SingleUseObjectProvider. This component, responsible for managing single-use key-value pairs, suffers from a lack of sufficient type and namespace isolation. The absence of proper isolation mechanisms allows a remote, unauthenticated attacker to manipulate the system by forging authorization codes. Successful exploitation allows for the creation of access tokens with administrative privileges. The vulnerability was published on April 2, 2026.

## Attack Chain

1.  The attacker sends a crafted request to the Keycloak server to initiate the authorization flow.
2.  The attacker leverages the lack of type and namespace isolation in the SingleUseObjectProvider.
3.  The attacker forges a valid authorization code using the vulnerability.
4.  The attacker presents the forged authorization code to the token endpoint.
5.  Keycloak validates the forged code due to the flawed SingleUseObjectProvider logic.
6.  The attacker receives an access token with elevated (admin) privileges.
7.  The attacker uses the admin-capable access token to perform administrative actions.
8.  The attacker gains full control over Keycloak resources and user data.

## Impact

Successful exploitation of CVE-2026-4282 allows a remote attacker to gain full administrative control over a Keycloak instance. This can lead to the compromise of all applications and services relying on Keycloak for authentication and authorization. The impact includes data breaches, account takeovers, and the potential for widespread service disruption. Given Keycloak's prevalence in securing web applications and APIs, the vulnerability poses a significant risk to organizations using affected versions.

## Recommendation

*   Apply the patch or upgrade to a version of Keycloak that resolves CVE-2026-4282 as soon as it becomes available from Red Hat.
*   Monitor Keycloak logs (webserver category, linux product) for suspicious requests to the authorization and token endpoints indicative of authorization code forging attempts.
*   Implement stricter input validation and sanitization on the authorization code parameter to mitigate the vulnerability.
