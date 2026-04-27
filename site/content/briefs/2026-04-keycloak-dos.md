---
title: Keycloak Denial-of-Service Vulnerability via Excessive Scope Parameter (CVE-2026-4634)
slug: 2026-04-keycloak-dos
description: An unauthenticated attacker can cause a denial-of-service on Keycloak servers by sending a crafted POST request to the OIDC token endpoint with an excessively long scope parameter, leading to high resource consumption.
date: "2026-04-02T13:16:27Z"
severities:
  - high
tags:
  - cve-2026-4634
  - denial-of-service
  - keycloak
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1498
    technique_name: Internal Defacement
cves:
  - id: CVE-2026-4634
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4634
  - https://access.redhat.com/security/cve/CVE-2026-4634
  - https://bugzilla.redhat.com/show_bug.cgi?id=2450250
rules:
  - title: Detect Suspiciously Long Scope Parameter
    description: Detects HTTP POST requests with excessively long scope parameters, potentially indicating exploitation of CVE-2026-4634.
    platform: sigma
    severity: high
    tactics:
      - availability
    techniques:
      - T1498
    data_sources:
      - webserver
      - linux
  - title: Keycloak OIDC Token Endpoint Access
    description: Detects access to the Keycloak OIDC token endpoint, useful for baselining and investigating potential attacks.
    platform: sigma
    severity: informational
    tactics:
      - discovery
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2026-4634 describes a denial-of-service vulnerability affecting Keycloak servers. This vulnerability allows an unauthenticated attacker to exhaust server resources by sending a specially crafted HTTP POST request to the OpenID Connect (OIDC) token endpoint. The malicious request includes an excessively long scope parameter, which forces the Keycloak server to consume significant processing time and memory. This can result in prolonged processing times for legitimate requests and ultimately…
