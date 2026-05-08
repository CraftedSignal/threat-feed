---
title: free5GC NEF 3gpp-traffic-influence API Unauthenticated Access
slug: 2026-05-free5gc-nef-auth-bypass
description: An unauthenticated API vulnerability in free5GC's NEF component allows attackers to create, read, patch, and delete traffic-influence subscriptions, potentially redirecting traffic and disrupting network services; the issue affects free5GC v4.2.1 and nef versions <= 1.2.3.
date: "2026-05-09T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - free5GC
  - nef
  - authentication bypass
  - traffic influence
  - cwe-306
  - cwe-862
vendors:
  - free5GC
products:
  - nef (<= 1.2.3)
  - free5GC
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1555
    technique_name: Credentials on Network Shares
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1068
    technique_name: Exploitation for Information Discovery
references:
  - https://github.com/advisories/GHSA-3p28-73q7-45xp
  - https://github.com/free5gc/free5gc/issues/859
  - https://github.com/free5gc/nef/pull/23
rules:
  - title: Detect Unauthorized Traffic Influence Subscription Creation
    description: Detects the creation of traffic influence subscriptions without a valid authorization header, indicating a potential authentication bypass.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
  - title: Detect Unauthorized Traffic Influence Subscription Modification
    description: Detects modification (PATCH) or deletion (DELETE) of traffic influence subscriptions without a valid authorization header, indicating a potential authentication bypass.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1098
    data_sources:
      - webserver
rules_count: 2
---

free5GC's Network Exposure Function (NEF) component is vulnerable to an unauthenticated API access issue. Specifically, the `3gpp-traffic-influence` API lacks inbound OAuth2/bearer-token authorization, allowing a network attacker with SBI access to create, read, patch, and delete traffic-influence subscriptions without proper authentication. This includes creating `AnyUeInd=true` subscriptions, affecting traffic steering for groups or all UEs. The vulnerability exists even when the service is supposedly disabled via configuration. This issue was validated against NEF container in the official Docker compose lab, source repo tag `v4.2.1`, running Docker image `free5gc/nef:v4.2.0`, runtime NEF commit `5ce35eab` and discovered on 2026-03-11. Successful exploitation can lead to significant disruption of network services.

## Attack Chain

1. The attacker gains network access to the SBI interface of the free5GC NEF.
2. The attacker sends a POST request to the `/:afID/subscriptions` endpoint of the `3gpp-traffic-influence` API to create a new traffic-influence subscription. The request may contain no `Authorization` header or a forged bearer token.
3. The NEF processes the request without authentication, allocating AF/subscription state and writing traffic-influence data, as defined in `NFs/nef/internal/sbi/processor/ti.go:50`.
4. The attacker sends a PATCH request to `/:afID/subscriptions/:subID` with a forged bearer token to modify the subscription.
5. The NEF processes the PATCH request, looking up and updating the subscription data, then attempts to call UDR/PCF, as defined in `NFs/nef/internal/sbi/processor/ti.go:279`. While this call might fail, the authentication bypass is confirmed.
6. Alternatively, the attacker sends a DELETE request to `/:afID/subscriptions/:subID` with a forged bearer token to remove the subscription.
7. The NEF processes the DELETE request, looking up and removing the subscription, as defined in `NFs/nef/internal/sbi/processor/ti.go:355`.
8. The attacker successfully manipulates traffic-steering policies, potentially redirecting traffic to attacker-controlled destinations or denying service.

## Impact

This vulnerability allows unauthorized manipulation of traffic-steering policies in the 5GC network. An attacker can create subscriptions to redirect AF traffic, read existing subscriptions to leak policy data, patch subscriptions to modify traffic steering, or delete subscriptions to cause denial of service. The fact that the `3gpp-traffic-influence` route group is reachable even when disabled via the `ServiceList` configuration exacerbates the risk. This can impact all users of the affected free5GC installation.

## Recommendation

*   Apply the upstream fix available at https://github.com/free5gc/nef/pull/23 to address the authentication bypass.
*   Deploy the Sigma rule "Detect Unauthorized Traffic Influence Subscription Creation" to detect unauthorized subscription creation attempts (see rule below).
*   Monitor web server logs for POST, PATCH, and DELETE requests to the `/3gpp-traffic-influence/v1/` endpoint without a valid `Authorization` header, using the example curl commands from the PoC as a baseline.
*   Block the listed malicious IPs (10.100.200.19, 192.0.2.40, 198.51.100.0, 10.60.0.1, 192.0.2.20, 10.60.0.2) on network devices to prevent potential exploitation attempts.
*   Ensure that the NEF service is properly configured and secured according to the latest free5GC security guidelines.
