---
title: DPDK GSO Library Out-of-Bounds Memory Access
slug: 2026-10-dpdk-gso-oob-access
description: A vulnerability in the DPDK Generic Segmentation Offload (GSO) library allows remote or guest-supplied packets to trigger out-of-bounds memory read or write operations due to insufficient header size validation.
date: "2026-10-14T18:33:58Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:dpdk:dpdk:*:*:*:*:*:*:*:*
vendors:
  - DPDK
products:
  - DPDK GSO library
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: A remote or guest-supplied packet processed with software GSO can trigger an out-of-bounds read or write.
    confidence_band: high
cves:
  - id: CVE-2026-100236
    cvss: 8.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-100236
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade DPDK framework to the version containing the patch for CVE-2026-100236
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-100236 advisory
  mitigation_plan:
    - priority: immediate
      action: Patch DPDK libraries in all production networking stacks and virtual switch configurations
      owner: IT Operations
      addresses: CVE-2026-100236
      evidence: CVE-2026-100236 advisory
---

A memory safety vulnerability (CVE-2026-100236) has been identified in the Data Plane Development Kit (DPDK) Generic Segmentation Offload (GSO) library. The flaw exists in the mechanism that copies packet headers into a new mbuf during the GSO process. Specifically, the library fails to perform bounds checking to ensure that the packet header fits within the source first segment or the destination buffer. If a supplied packet header exceeds the configured GSO segment size, it triggers an underflow in the payload-size calculation. This vulnerability can be leveraged by a remote attacker or a malicious guest to perform out-of-bounds memory reads or writes, potentially leading to arbitrary code execution or system instability within the networking stack. This is critical for environments utilizing high-performance packet processing, such as virtual switches or NFV infrastructure.

## Impact

The vulnerability impacts systems utilizing the DPDK framework for packet processing, particularly those exposed to untrusted network traffic or multi-tenant guest workloads. Successful exploitation can result in unauthorized memory access, causing memory corruption, system crashes, or potential elevation of privilege within the networking context. Given the core role of DPDK in virtualized environments, this flaw poses a significant risk to the integrity and availability of network infrastructure.

## Recommendation

* Upgrade all instances of the DPDK framework to the latest stable release that addresses CVE-2026-100236.
* Monitor network traffic for malformed packets or anomalous header structures that may indicate exploitation attempts against the GSO implementation.
* Isolate workloads utilizing DPDK to minimize the exposure of the networking stack to untrusted guest-originated traffic where possible.
