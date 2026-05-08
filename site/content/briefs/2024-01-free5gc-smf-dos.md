---
title: free5GC SMF Unauthenticated Process-Kill Denial-of-Service via UPI Endpoint
slug: 2024-01-free5gc-smf-dos
description: free5GC's SMF is vulnerable to an unauthenticated denial-of-service attack where a crafted POST request to the `/upi/v1/upNodesLinks` endpoint can trigger a `Fatalf` call, terminating the entire SMF process, effectively disrupting network services.
date: "2026-05-08T22:47:24Z"
type: threat
types:
  - threat
severities:
  - medium
tags:
  - free5GC
  - SMF
  - DoS
  - unauthenticated
  - UPI
  - CVE-2026-44321
vendors:
  - free5GC
products:
  - SMF
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://github.com/advisories/GHSA-44qj-cghf-9p97
  - https://github.com/free5gc/free5gc/issues/906
  - https://github.com/free5gc/smf/pull/203
iocs:
  - type: cidr
    value: 10.60.0.0/16
ioc_counts:
  cidr: 1
rules:
  - title: Detect Free5GC SMF UPI POST UPF Configuration
    description: Detects suspicious POST requests to the free5GC SMF UPI endpoint used for UPF configuration that may indicate unauthorized configuration changes or denial-of-service attempts.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1499.004
    data_sources:
      - webserver
  - title: Detect Free5GC SMF Process Exit Due to Overlapping CIDR
    description: Detects the free5GC SMF process exiting with a specific error message indicating an overlap in CIDR values, which can be triggered by a malicious request to the UPI endpoint.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1499.004
    data_sources:
      - application
rules_count: 2
---

The free5GC Session Management Function (SMF) is susceptible to a denial-of-service attack due to missing authentication on the `UPI` management route group. Specifically, the `POST /upi/v1/upNodesLinks` endpoint lacks proper inbound OAuth2 middleware, allowing unauthenticated requests. An attacker can send a crafted JSON payload to this endpoint, which is then processed by `UpNodesFromConfiguration()`. Certain validation failures, such as overlapping UE-IP-pools, trigger a `logger.InitLog.Fatalf(...)` call, which terminates the entire SMF process. This is more severe than a simple panic, as `Fatalf` is equivalent to `os.Exit(1)` and halts the entire SMF process, impacting PDU-session establishment and UE policy lookups. The vulnerability affects free5GC version 4.2.1.

## Attack Chain

1. The attacker identifies the vulnerable `POST /upi/v1/upNodesLinks` endpoint on the SMF SBI (Service Based Interface), typically running on port 8000.
2. The attacker crafts a malicious JSON payload containing UPF (User Plane Function) configuration data.
3. The crafted JSON includes a UE-IP-pool that overlaps with an existing UPF's pool (e.g., `10.60.0.0/16`).
4. The attacker sends an unauthenticated POST request to the `/upi/v1/upNodesLinks` endpoint with the malicious JSON payload.
5. The SMF processes the request and passes the JSON data to the `UpNodesFromConfiguration()` function.
6. The `UpNodesFromConfiguration()` function calls `isOverlap(allUEIPPools)` to validate the UE-IP-pools.
7. The `isOverlap` function detects the overlapping CIDR value between the attacker-provided UPF and the existing UPF configuration.
8. The `isOverlap` function triggers a `logger.InitLog.Fatalf("overlap cidr value between UPFs")` call, which terminates the entire SMF process due to the equivalent of `os.Exit(1)`.

## Impact

This vulnerability allows an unauthenticated attacker to cause a complete denial-of-service on the free5GC SMF. The attacker only needs network access to the SMF SBI and can repeatedly send the malicious POST request to keep the SMF process terminated after each restart. This impacts all SMF services, including PDU-session establishment and UE policy interactions, leading to network connectivity disruptions. This vulnerability affects free5GC v4.2.1.

## Recommendation

*   Apply the official patch from the upstream fix at [https://github.com/free5gc/smf/pull/203](https://github.com/free5gc/smf/pull/203) to mitigate CVE-2026-44321.
*   Implement network access controls to restrict access to the SMF SBI from untrusted networks.
*   Deploy the Sigma rule `Detect Free5GC SMF UPI POST UPF Configuration` to detect suspicious POST requests to the `/upi/v1/upNodesLinks` endpoint.
*   Monitor SMF container logs for the `FATA` message `overlap cidr value between UPFs` indicating a process termination.
*   Consider using the `webserver` Sigma rules in this brief to detect unauthorized requests to the `/upi/v1/upNodesLinks` endpoint.
