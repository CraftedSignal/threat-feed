---
title: free5GC NEF Unauthenticated Callback Vulnerability
slug: 2024-01-02-free5gc-nef-auth-bypass
description: free5GC NEF v4.2.1 exposes an unauthenticated callback route group, enabling attackers to forge SMF callbacks and potentially corrupt AF traffic-influence or PFD-management subscription views, leading to unauthorized policy changes.
date: "2024-01-02T18:30:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - 5G
  - NEF
  - Authentication Bypass
  - CWE-306
  - CWE-862
vendors:
  - free5GC
products:
  - nef:v4.2.1
  - go/github.com/free5gc/nef (<= 1.2.3)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1555
    technique_name: Credentials from Password Stores
references:
  - https://github.com/advisories/GHSA-wqfh-gq79-j8mf
rules:
  - title: Detect Unauthenticated NEF Callback Request
    description: Detects attempts to exploit the unauthenticated NEF callback vulnerability by identifying requests with invalid or suspicious authorization headers.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect NEF Callback with Empty Authorization Header
    description: Detects NEF callback requests to the /nnef-callback endpoint with an empty or missing Authorization header, indicating a potential exploit attempt.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

The free5GC NEF (Network Exposure Function) version 4.2.1 contains a critical vulnerability stemming from the lack of inbound authentication on the `nnef-callback` route group. This oversight allows an attacker to send forged SMF (Service Management Function) callback requests to the NEF without proper authorization. The vulnerability lies in the fact that the API layer processes the request body and deserializes it before any authentication check is performed. This can lead to corruption of AF (Application Function) traffic-influence or PFD (Packet Flow Description) management subscription views and influence downstream SMF/UPF (User Plane Function) policy decisions. The `nnef-callback` route group remains reachable even when the runtime `ServiceList` does not declare it, undermining intended service disabling mechanisms.

## Attack Chain

1.  Attacker identifies a reachable NEF instance running free5GC v4.2.1.
2.  Attacker crafts a malicious SMF callback request targeting the `/nnef-callback/v1/notification/smf` endpoint.
3.  The attacker sets the `Authorization` header with a forged or arbitrary bearer token (e.g., `Authorization: Bearer not-a-real-token`).
4.  The NEF server receives the request and, due to the missing authentication middleware, parses the request body without validating the token.
5.  The callback handler within the NEF processes the request and attempts to look up subscription state using the provided `NotifId`.
6.  If the `NotifId` is valid, the attacker can manipulate subscription data, leading to traffic-influence or PFD-management corruption.
7.  The corrupted subscription data influences downstream SMF/UPF policy decisions, potentially diverting traffic or modifying service quality.
8.  Attacker gains unauthorized control over network traffic and subscriber experience.

## Impact

The lack of authentication on the `nnef-callback` route group allows any party that can reach the NEF on the SBI (Service Based Interface) to submit forged SMF callbacks anonymously. An attacker who can guess or obtain a valid `NotifId` can deliver forged event notifications against real subscription state, corrupting AF traffic-influence and PFD-management subscription views, and subsequently influencing downstream SMF/UPF policy decisions. The vulnerability can lead to unauthorized traffic diversion, service disruption, or modification of service quality for subscribers. The affected version is free5GC v4.2.1, potentially impacting deployments of this version in various telecommunications networks.

## Recommendation

*   Deploy the Sigma rule `Detect Unauthenticated NEF Callback Request` to identify attempts to exploit the vulnerability by detecting requests to the `/nnef-callback/v1/notification/smf` endpoint with invalid or suspicious authorization headers (see rule below).
*   Monitor web server logs for unauthorized POST requests to the `/nnef-callback/v1/notification/smf` endpoint, referencing the IP address `10.100.200.19` from the provided PoC.
*   Upgrade to a patched version of free5GC NEF that addresses the authentication vulnerability (see upstream fix at https://github.com/free5gc/nef/pull/24).
*   Apply input validation and authorization checks on all SBI endpoints, especially callback handlers, to prevent unauthorized access and data manipulation.
*   Review and harden the NEF configuration to ensure that only authorized services and endpoints are exposed, mitigating the risk of unauthorized access.
