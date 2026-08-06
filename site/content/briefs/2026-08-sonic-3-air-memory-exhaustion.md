---
title: Unbounded Memory Allocation Vulnerability in Sonic 3 A.I.R.
slug: 2026-08-sonic-3-air-memory-exhaustion
description: Sonic 3 A.I.R. versions before commit 2492d18 are vulnerable to a remote denial-of-service attack due to improper bounds checking on UDP packet IDs, leading to memory exhaustion and server crashes.
date: "2026-08-06T13:24:19Z"
type: advisory
types:
  - advisory
severities:
  - low
products:
  - Sonic 3 A.I.R.
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: An unauthenticated remote attacker can exploit this by sending a crafted packet with a maximum uint32 value, causing the server to exhaust system memory and trigger a crash.
    confidence_band: high
cves:
  - id: CVE-2026-66733
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-66733
action_plan:
  priority: elevated
  owners:
    - IT Operations
  mitigation_plan:
    - priority: immediate
      action: Upgrade Sonic 3 A.I.R. to commit 2492d18 or later.
      owner: IT Operations
      addresses: CVE-2026-66733
      evidence: Source explicitly identifies commit 2492d18 as the patch version.
---

Sonic 3 A.I.R. (Angel Island Revisited) contains a memory exhaustion vulnerability (CVE-2026-66733) located within the `ReceivedPacketCache::enqueuePacket()` function. The flaw stems from a lack of bounds checking on the `mUniquePacketID` field parsed from incoming UDP packets. An unauthenticated remote attacker can exploit this by crafting a UDP packet containing the maximum possible uint32 value for the `mUniquePacketID`. 

Upon receipt, the application attempts to allocate a `CacheItem` object for every packet ID gap between the current state and the provided maximum ID. This results in an uncontrolled memory allocation sequence that exhausts the available host system memory. The process fails to handle the resulting `std::bad_alloc` exception, which propagates to `std::terminate()`, causing an immediate server process crash. This vulnerability impacts all deployments of the application before commit 2492d18, affecting Windows, Linux, and macOS environments.

## Impact

Successful exploitation results in a persistent denial-of-service condition for the targeted Sonic 3 A.I.R. instance. As the crash is triggered by an uncaught exception, the server process will cease functioning, requiring a manual restart by an administrator. This vulnerability poses a significant risk to publicly accessible instances, as it requires no authentication to execute, allowing any remote user to crash the service.

## Recommendation

* Update Sonic 3 A.I.R. to commit 2492d18 or later immediately to apply the patch for CVE-2026-66733.
* If updating is not immediately possible, restrict network access to the UDP port used by the server to trusted IP addresses only, using host-based firewalls or network access control lists.
* Monitor system memory usage on the host running the server process; sudden, abnormal spikes in memory consumption associated with the process may indicate exploitation attempts.
