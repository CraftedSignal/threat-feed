---
title: free5GC NEF Unauthenticated OAM Route Group
slug: 2026-05-free5gc-nef-auth-bypass
description: free5GC's NEF (Network Exposure Function) has an unauthenticated OAM (Operations, Administration, and Maintenance) route group, allowing unauthorized access to OAM functionalities because the `nnef-oam` route group lacks inbound OAuth2/bearer-token authorization, enabling network attackers to access the OAM route without any authentication.
date: "2026-05-09T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - free5GC
  - NEF
  - authentication bypass
  - CWE-306
  - CWE-862
  - unauthenticated access
vendors:
  - free5GC
products:
  - nef
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1586
    technique_name: Compromise Appliance
references:
  - https://github.com/advisories/GHSA-cmpj-2x3g-m7g3
  - https://github.com/free5gc/free5gc/issues/861
  - https://github.com/free5gc/nef/pull/23
rules:
  - title: Detect CVE-2026-44327 Attempt — Unauthenticated Access to NEF OAM Route
    description: Detects CVE-2026-44327 attempt — Unauthenticated GET requests to the NEF OAM route (`/nnef-oam/v1/`) without an Authorization header.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1586.002
    data_sources:
      - webserver
  - title: Detect CVE-2026-44327 Successful Access — Unauthenticated 200 OK Response from NEF OAM Route
    description: Detects CVE-2026-44327 exploitation — 200 OK response from the NEF OAM route (`/nnef-oam/v1/`) following a GET request without an Authorization header.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1586.002
    data_sources:
      - webserver
rules_count: 2
---

free5GC's Network Exposure Function (NEF) is vulnerable to an authentication bypass in its Operations, Administration, and Maintenance (OAM) route group. The vulnerability, identified in version v4.2.1, stems from the `nnef-oam` route group being mounted without any inbound OAuth2/bearer-token authorization. This allows a network attacker, who can reach the NEF on the Service Based Interface (SBI), to access the OAM route without providing any authentication credentials. Although the current OAM handler is a stub that returns null, the core issue is the absence of authentication middleware at the route group level. This means that any future OAM operations added to this route group will inherit the same missing authentication boundary, posing a significant risk of unauthorized access to sensitive OAM functionalities. This vulnerability was validated against the NEF container in the official Docker compose lab using the `free5gc/nef:v4.2.0` Docker image and runtime NEF commit `5ce35eab` on 2026-03-11. The reported CVE is CVE-2026-44327.

## Attack Chain

1. An attacker identifies the NEF service running on the SBI, typically on port 8000.
2. The attacker sends a GET request to the `/nnef-oam/v1/` endpoint without any `Authorization` header.
3. The NEF server, lacking inbound authentication middleware for the OAM route group, accepts the request without authentication.
4. The OAM handler, currently a stub, processes the request and returns a `200 OK` response with a `null` payload.
5. The attacker probes and enumerates the available OAM route surface to identify potential future endpoints.
6. If future OAM endpoints are added to the vulnerable route group, the attacker can access them without authentication.
7. The attacker can potentially perform unauthorized operations such as reading configuration data, modifying settings, or restarting services, depending on the functionality of the future OAM endpoints.
8. Successful exploitation allows the attacker to compromise the availability and integrity of the 5GC network.

## Impact

This vulnerability (CVE-2026-44327) allows unauthorized access to the NEF's OAM functionalities. While the current OAM handler is a stub, the lack of authentication on the route group means any future OAM operations will be exposed. An attacker could probe the OAM route surface and access sensitive OAM functionalities in the future. This could allow an attacker to gain unauthorized control over the NEF, potentially disrupting or compromising the 5GC network it supports. Operators who assume OAuth2 is enforced on all NEF interfaces are misled by the `OAuth2 setting receive from NRF: true` configuration, which does not apply to this specific OAM route group.

## Recommendation

*   Apply the upstream fix available at [https://github.com/free5gc/nef/pull/23](https://github.com/free5gc/nef/pull/23) to remediate the vulnerability.
*   Monitor network traffic to the NEF SBI for requests to the `/nnef-oam/v1/` endpoint without an `Authorization` header using the provided Sigma rule.
*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment.
*   Apply any available patches from free5GC to address CVE-2026-44327 on affected NEF deployments.
