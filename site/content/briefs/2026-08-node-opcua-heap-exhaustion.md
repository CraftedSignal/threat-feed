---
title: Unauthenticated Heap Exhaustion DoS in node-opcua
slug: 2026-08-node-opcua-heap-exhaustion
description: An unbounded nonce cache in the node-opcua library allows unauthenticated remote attackers to trigger heap memory exhaustion and process crashes via repeated session creation requests.
date: "2026-08-20T19:14:13Z"
type: advisory
types:
  - advisory
severities:
  - medium
products:
  - node-opcua
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: An unauthenticated remote attacker can exploit the CreateSession path to accumulate nonce entries indefinitely, causing the node-opcua server process to crash.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-6wvw-vrw4-363w
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-54156
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade node-opcua library to a version containing a nonce eviction policy.
      owner: IT Operations
      due: 72h
      evidence: Source suggests adding a TTL-based eviction policy.
  mitigation_plan:
    - priority: immediate
      action: Configure rate-limiting on OPC UA endpoints to prevent rapid nonce cache growth.
      owner: Security Engineering
      addresses: CVE-2026-54156
      evidence: The cache is populated by OpenSecureChannel and CreateSession requests; limiting these mitigates the attack vector.
---

The node-opcua library, specifically versions 2.165.0 and earlier, contains a critical vulnerability (CVE-2026-54156) in its secure channel layer. The library maintains a process-global object, `g_alreadyUsedNonce`, to track nonces for replay detection. This cache lacks an eviction policy, causing it to grow indefinitely as it records every `OpenSecureChannelRequest` and `CreateSession` request processed by the server. 

An unauthenticated remote attacker can exploit this by repeatedly initiating `CreateSession` requests, which do not require prior authentication or valid certificates. Because these nonce entries persist even after session expiry, the server's heap memory usage grows linearly with the number of requests until the Node.js process reaches its heap limit and crashes. This vulnerability represents a significant Denial of Service (DoS) risk for industrial systems utilizing node-opcua for OPC UA communications.

## Impact

Successful exploitation leads to a Denial of Service (DoS) of the node-opcua server process. Empirical testing indicates that 5,000 unique nonces increase resident heap usage by approximately 1.23 MB. Extrapolating this growth to 1,000,000 requests results in a memory footprint increase of approximately 246 MB, which is sufficient to exhaust default Node.js heap limits in many operational environments, forcing a process crash and service interruption.

## Recommendation

- Upgrade to a patched version of node-opcua that implements a TTL-based eviction policy for the nonce cache.
- If immediate patching is not possible, implement rate-limiting at the network layer for `CreateSession` and `OpenSecureChannel` requests to slow the rate of cache growth.
- Deploy monitoring for node-opcua memory utilization; alerts should be configured to trigger on anomalous heap growth or rapidly increasing memory consumption by the application process.
