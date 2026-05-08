---
title: free5GC NEF nnef-pfdmanagement API Unauthenticated Access Vulnerability
slug: 2026-05-free5gc-nef-auth-bypass
description: free5GC's NEF nnef-pfdmanagement API is vulnerable to unauthenticated access, allowing attackers with network access to read PFD data and create/delete PFD subscriptions by using forged bearer tokens due to the absence of inbound OAuth2/bearer-token authorization.
date: "2026-05-09T14:30:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - free5GC
  - NEF
  - unauthenticated access
  - CVE-2026-44330
  - PFD management
  - network security
vendors:
  - free5GC
products:
  - nef (<= 1.2.3)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-rwww-x45w-p52w
  - https://github.com/free5gc/free5gc/issues/862
  - https://github.com/free5gc/nef/pull/23
iocs:
  - type: url
    value: http://10.100.200.19:8000/nnef-pfdmanagement/v1/applications?application-ids=app-poc-pfdf-read-20260311
  - type: url
    value: http://10.100.200.19:8000/nnef-pfdmanagement/v1/applications/app-poc-pfdf-read-20260311
  - type: url
    value: http://10.100.200.19:8000/nnef-pfdmanagement/v1/subscriptions
  - type: url
    value: http://10.100.200.19:8000/nnef-pfdmanagement/v1/subscriptions/1
ioc_counts:
  url: 4
rules:
  - title: Detect Forged Token Access to free5GC NEF PFD Data
    description: Detects CVE-2026-44330 exploitation — unauthorized attempts to access PFD data in free5GC NEF via nnef-pfdmanagement API with forged bearer token.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect Forged Token Subscription Manipulation in free5GC NEF
    description: Detects CVE-2026-44330 exploitation — unauthorized attempts to create or delete PFD subscriptions in free5GC NEF via nnef-pfdmanagement API with forged bearer token.
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

The free5GC Network Exposure Function (NEF) is vulnerable to an unauthenticated access issue within the `nnef-pfdmanagement` API. The vulnerability, present in versions up to v4.2.1, stems from a missing inbound OAuth2/bearer-token authorization check on the `nnef-pfdmanagement` route group. This oversight allows any network attacker capable of reaching the NEF on the SBI (Service Based Interface) to bypass authentication using forged bearer tokens. The `nnef-pfdmanagement` API is intended for production use, as it is declared in the runtime `ServiceList` and should be protected by OAuth2 authentication. This vulnerability allows attackers to read PFD application data and manipulate PFD change-notification subscriptions without proper authorization.

## Attack Chain

1.  Attacker gains network access to the free5GC NEF SBI (Service Based Interface), typically running on port 8000.
2.  Attacker crafts a malicious HTTP GET request to the `/nnef-pfdmanagement/v1/applications` endpoint, including a forged or arbitrary bearer token in the `Authorization` header.
3.  NEF processes the request without proper authentication, querying the UDR (Unified Data Repository) for PFD data.
4.  NEF returns the PFD application data to the attacker, exposing sensitive traffic-classification policies.
5.  Attacker crafts a malicious HTTP POST request to the `/nnef-pfdmanagement/v1/subscriptions` endpoint with a forged bearer token, including a `notifyUri` pointing to an attacker-controlled endpoint.
6.  NEF creates the PFD subscription, directing change notifications to the attacker's `notifyUri`.
7.  Attacker crafts a malicious HTTP DELETE request to `/nnef-pfdmanagement/v1/subscriptions/{subID}` with a forged bearer token, targeting a legitimate subscription.
8.  NEF deletes the targeted PFD subscription, disrupting legitimate change notifications.

## Impact

The unauthenticated access vulnerability in free5GC's NEF v4.2.1 allows attackers to read AF-supplied PFD application data, create attacker-controlled PFD change-notification subscriptions, and delete legitimate PFD subscriptions. Successful exploitation can lead to the leakage of traffic-classification policies, turning NEF into an unauthenticated outbound HTTP request source, and disrupting legitimate PFD-update propagation. This vulnerability affects the intended production path for PFD services, posing a critical risk to 5G network operators.

## Recommendation

*   Deploy the Sigma rule `Detect Forged Token Access to free5GC NEF PFD Data` to detect unauthorized attempts to access PFD data via the `nnef-pfdmanagement` API.
*   Deploy the Sigma rule `Detect Forged Token Subscription Manipulation in free5GC NEF` to detect unauthorized attempts to create or delete PFD subscriptions via the `nnef-pfdmanagement` API.
*   Apply the patch or upgrade to a fixed version of free5GC NEF that addresses CVE-2026-44330.
*   Monitor network traffic to the NEF SBI (IP address `10.100.200.19`) for suspicious activity related to the `/nnef-pfdmanagement/v1/` endpoints listed in the IOC table.
