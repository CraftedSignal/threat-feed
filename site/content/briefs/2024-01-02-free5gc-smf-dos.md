---
title: free5GC SMF Unauthenticated State-Mutating Panic-DoS Vulnerability
slug: 2024-01-02-free5gc-smf-dos
description: free5GC's SMF is vulnerable to an unauthenticated denial-of-service attack where a crafted DELETE request to the /upi/v1/upNodesLinks/{ref} endpoint triggers a nil-pointer dereference, causing a panic and mutating the in-memory user-plane topology, impacting the selection of UPFs for legitimate UE sessions.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - free5GC
  - dos
  - vulnerability
vendors:
  - free5GC
products:
  - free5GC SMF
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071.001
    technique_name: 'Application Layer Protocol: Web Protocols'
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Denial of Service
references:
  - https://github.com/advisories/GHSA-p9mg-74mg-cwwr
  - https://github.com/free5gc/free5gc/issues/905
  - https://github.com/free5gc/smf/pull/199
iocs:
  - type: url
    value: http://10.100.200.6:8000/nsmf-oam/v1/
  - type: url
    value: http://10.100.200.6:8000/upi/v1/upNodesLinks/gNB1
ioc_counts:
  url: 2
rules:
  - title: Detect Unauthenticated SMF UPI DELETE Request
    description: Detects unauthenticated DELETE requests to the SMF UPI endpoint, indicative of a potential denial-of-service attack.
    platform: sigma
    severity: high
    tactics:
      - availability
    techniques:
      - T1498
    data_sources:
      - webserver
  - title: Detect SMF Server Error After UPI DELETE Request
    description: Detects a 500 Internal Server Error in SMF logs immediately following a DELETE request to the UPI endpoint, suggesting a potential exploit attempt.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1498
    data_sources:
      - webserver
rules_count: 2
---

free5GC's SMF (Session Management Function) contains a vulnerability where the `UPI` (User Plane Interface) management route group lacks proper authentication, exposing it to unauthenticated attacks. Specifically, the `DELETE /upi/v1/upNodesLinks/{upNodeRef}` handler attempts to dereference a potentially nil `UPF` (User Plane Function) pointer, leading to a nil-pointer dereference and panic. This occurs because `AN`-typed (Access Node) nodes are constructed without a `UPF` object. An attacker can exploit this by sending an unauthenticated DELETE request, such as `DELETE /upi/v1/upNodesLinks/gNB1`, crashing the handler and, critically, mutating the in-memory user-plane topology before the panic occurs. This allows an off-path network attacker to trigger a state-mutating panic-DoS against any AN entry by name. This vulnerability affects free5GC version 4.2.1.

## Attack Chain

1. An attacker identifies a vulnerable free5GC SMF instance with the exposed UPI endpoint.
2. The attacker crafts a DELETE request targeting the `/upi/v1/upNodesLinks/{upNodeRef}` endpoint, specifying an AN node name (e.g., `gNB1`) without any authentication credentials.
3. The attacker sends the unauthenticated DELETE request to the SMF instance.
4. The SMF receives the request and proceeds to process it within the `DeleteUpNodeLink` handler.
5. The handler identifies the target node as an AN type and executes `UpNodeDelete(upNodeRef)`, which mutates the in-memory user-plane topology, deleting the specified AN entry.
6. The handler then attempts to dereference the `UPF` field of the AN node, which is nil for AN nodes by design.
7. This dereference results in a nil-pointer dereference, causing a panic in the SMF process.
8. The SMF returns a 500 Internal Server Error, but the topology has already been mutated, denying SMF's ability to consider that AN in subsequent UPF selection.

## Impact

The vulnerability allows an unauthenticated attacker to perform a denial-of-service attack against the free5GC SMF. By sending a single, unauthenticated DELETE request, an attacker can delete arbitrary named entries from SMF's in-memory user-plane topology and trigger a panic. This impacts SMF's ability to select UPFs and establish PFCP paths for legitimate UE sessions. The attacker can repeat this process against any AN entry, sustaining the topology denial without needing to authenticate. This can lead to service disruption and impact the availability of the 5G network.

## Recommendation

*   Apply the upstream fix available at [https://github.com/free5gc/smf/pull/199](https://github.com/free5gc/smf/pull/199) to patch the nil-pointer dereference in the `DeleteUpNodeLink` handler.
*   Implement authentication and authorization middleware on the `UPI` route group to prevent unauthenticated access, as demonstrated in the `nsmf-oam` route group; monitor webserver logs for `DELETE` requests to the `/upi/v1/upNodesLinks/` endpoint without valid authentication headers.
*   Deploy the Sigma rule `Detect Unauthenticated SMF UPI DELETE Request` to identify unauthenticated DELETE requests to the vulnerable endpoint, monitoring webserver logs.
