---
brief_id: brief-2026-10-25-openthread-mdns-dos
event_id: brief-2026-10-25-openthread-mdns-dos
revision: 1
activity_at: "2026-10-25T21:47:04Z"
title: 'OpenThread: mDNS discovery proxy denial of service (CVE-2026-112325)'
slug: 2026-10-openthread-mdns-dos
description: A NULL-pointer dereference vulnerability in the OpenThread DNS-SD Discovery Proxy allows a remote attacker on the same Thread mesh to trigger a denial of service on the Border Router via two crafted DNS-SD queries.
date: "2026-10-25T21:47:04Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Verified against GHSA-xf9m-rgrq-7vqf and vendor commit history
cpes:
  - cpe:2.3:a:openthread:openthread:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - iot
  - openthread
  - mdns
vendors:
  - OpenThread
products:
  - OpenThread (< b47613f1)
  - OpenThread Border Router (< b47613f1)
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1498
    technique_name: Network Denial of Service
    evidence: A remotely triggerable NULL-pointer dereference in OpenThread's native Multicast DNS (mDNS) / DNS-SD Discovery Proxy... crashes a default-configuration OpenThread Border Router (OTBR), taking the whole Thread network off-network.
    confidence_band: high
cves:
  - id: CVE-2026-112325
    kev_status: unknown
references:
  - https://github.com/openthread/openthread/security/advisories/GHSA-xf9m-rgrq-7vqf
  - https://vulners.com/cve/CVE-2026-112325
  - https://github.com/openthread/openthread/commit/b47613f1f5d5104c3168daacb696d7ea19834568
  - https://sploitus.com/exploit?id=B910636D-F009-5936-ABE2-290770E39363&utm_source=rss&utm_medium=rss
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade OpenThread Border Router to a version containing commit b47613f1
      owner: IT Operations
      due: 48h
      evidence: 'Fixed upstream in PR #13653, merged as b47613f1'
  hunt_leads:
    - lead: Monitor Border Router logs for recurring unexpected service restarts or segmentation faults
      technique_id: T1498
      data_needed:
        - Systemd/kernel crash logs from OTBR hosts
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: 'Full AddressSanitizer output: evidence/asan_radio_path.txt'
---

OpenThread's native Multicast DNS (mDNS) implementation contains a vulnerability in the `Core::RecordCache::Matches()` function. The function fails to validate that the `mNextLabels` pointer of an incoming DNS-SD querier is non-NULL before passing it to `NameMatch()`. An attacker on a Thread mesh can send two specific, well-formed DNS-SD query packets that cause the `Matches()` function to dereference a NULL pointer, crashing the OpenThread Border Router (OTBR). This results in a denial of service (DoS) for the entire Thread network, as the router loses its capability to facilitate off-network connectivity.

## Attack Chain
1. An attacker gains access to a device on the Thread mesh (e.g., a compromised IoT sensor or light bulb).
2. The attacker sends a first DNS-SD query (`QNAME`: `default.service.arpa.default.service.arpa`) to the Border Router.
3. The Border Router processes the query, resulting in a cache entry with a non-NULL `mNextLabels` value.
4. The attacker sends a second DNS-SD query (`QNAME`: `default.service.arpa`).
5. The `StripDomainName()` function fails to strip the domain, resulting in an incoming querier with `mNextLabels = nullptr`.
6. The `RecordCache::Matches()` function executes, comparing the new query against the cached entry.
7. The `RecordCache::Matches()` function enters the `else` branch, invoking `NameMatch()` without checking if the querier's `mNextLabels` is NULL.
8. `NameMatch()` dereferences the NULL pointer (address 0x0), crashing the process.

## Impact
The crash causes an immediate denial of service on the OpenThread Border Router. Because the Border Router acts as the gateway between the Thread mesh and external networks, the entire Thread network is cut off from off-network connectivity until the service or device is manually recovered.

## Recommendation
- Upgrade OpenThread and OpenThread Border Router (OTBR) to a revision containing commit `b47613f1` or later.
- Audit mesh networks for unauthorized devices, as the exploit requires adjacency to the Thread interface.
- Implement monitoring for service crashes on Border Router hardware to identify potential exploitation attempts.
