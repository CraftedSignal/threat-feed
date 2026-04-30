---
title: Keycloak Denial-of-Service Vulnerability via Excessive Scope Parameter (CVE-2026-4634)
slug: 2026-04-keycloak-dos
description: An unauthenticated attacker can cause a denial-of-service on Keycloak servers by sending a crafted POST request to the OIDC token endpoint with an excessively long scope parameter, leading to high resource consumption.
date: "2026-04-02T13:16:27Z"
severities:
  - high
type: advisory
types:
  - advisory
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

CVE-2026-4634 describes a denial-of-service vulnerability affecting Keycloak servers. This vulnerability allows an unauthenticated attacker to exhaust server resources by sending a specially crafted HTTP POST request to the OpenID Connect (OIDC) token endpoint. The malicious request includes an excessively long scope parameter, which forces the Keycloak server to consume significant processing time and memory. This can result in prolonged processing times for legitimate requests and ultimately a denial of service for all users of the affected Keycloak instance. The vulnerability was reported on April 2, 2026, and affects unpatched versions of Keycloak. Defenders should prioritize patching and consider implementing rate limiting to mitigate the impact of this vulnerability.

## Attack Chain

1.  The attacker identifies a vulnerable Keycloak instance.
2.  The attacker crafts an HTTP POST request targeted at the OIDC token endpoint (e.g., `/auth/realms/{realm-name}/protocol/openid-connect/token`).
3.  The attacker includes a `scope` parameter in the POST request.
4.  The attacker sets the value of the `scope` parameter to an extremely long string, causing the Keycloak server to allocate excessive resources when processing it.
5.  The attacker sends the malicious POST request to the Keycloak server.
6.  The Keycloak server attempts to process the excessively long `scope` parameter, consuming CPU and memory resources.
7.  Repeated requests from the attacker further exhaust server resources.
8.  The Keycloak server becomes unresponsive, leading to a denial of service for legitimate users.

## Impact

Successful exploitation of CVE-2026-4634 results in a denial-of-service condition, rendering the Keycloak server unavailable. This impacts all applications and services relying on Keycloak for authentication and authorization. The number of affected users depends on the size and criticality of the Keycloak deployment. Organizations in any sector using Keycloak are potentially vulnerable. Unavailability can disrupt business operations, impacting productivity and revenue.

## Recommendation

*   Apply the security patch released by Red Hat/Keycloak to address CVE-2026-4634 to eliminate the vulnerability.
*   Implement rate limiting on the OIDC token endpoint to restrict the number of requests from a single IP address within a given timeframe.
*   Monitor web server logs for suspicious POST requests to the OIDC token endpoint with unusually long `scope` parameters to detect potential exploitation attempts and deploy the Sigma rule `Detect Suspiciously Long Scope Parameter`.
*   Consider deploying a web application firewall (WAF) rule to block requests with excessively long scope parameters.
