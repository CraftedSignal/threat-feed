---
title: Keycloak Authorization Code Forging Vulnerability (CVE-2026-4282)
slug: 2026-04-keycloak-privesc
description: An unauthenticated attacker can exploit CVE-2026-4282 in Keycloak's SingleUseObjectProvider to forge authorization codes, leading to privilege escalation and the creation of admin-capable access tokens.
date: "2026-04-02T13:16:26Z"
severities:
  - high
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

CVE-2026-4282 identifies a critical vulnerability within the Keycloak authentication server, specifically affecting the SingleUseObjectProvider. This component, responsible for managing single-use key-value pairs, suffers from a lack of sufficient type and namespace isolation. The absence of proper isolation mechanisms allows a remote, unauthenticated attacker to manipulate the system by forging authorization codes. Successful exploitation allows for the creation of access tokens with…
