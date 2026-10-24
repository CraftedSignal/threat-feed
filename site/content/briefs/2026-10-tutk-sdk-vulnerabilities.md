---
brief_id: brief-2026-10-24-tutk-sdk-vulnerabilities
event_id: brief-2026-10-24-tutk-sdk-vulnerabilities
revision: 1
activity_at: "2026-10-24T20:28:11Z"
title: 'ThroughTek TUTK SDK: Heap Overflow and Out-of-Bounds Read (CVE-2026-38698 and CVE-2026-38699)'
slug: 2026-10-tutk-sdk-vulnerabilities
description: Public proof-of-concept exploits are available for two vulnerabilities in the ThroughTek TUTK SDK (v3.1.10.0-4.3.8.1) that could allow remote heap overflow and out-of-bounds read conditions in downstream IoT devices.
date: "2026-10-24T20:28:11Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "3"
  rating: B3
  likelihood: roughly even chance
qa_status:
  verdict: pass
  validation_status: Source corroborated by public research references.
tags:
  - iot
  - vulnerability
  - cve
vendors:
  - ThroughTek
products:
  - TUTK SDK (v.3.1.10.0 through v.4.3.8.1)
cves:
  - id: CVE-2026-38698
    kev_status: unknown
  - id: CVE-2026-38699
    kev_status: unknown
references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-VITAL-INFORMATION-RESOURCE-UNDER-SIEGE-CVE-2026-38698-AND-CVE-2026-38699
  - https://github.com/blasty/unwyze
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-VITAL-INFORMATION-RESOURCE-UNDER-SIEGE-CVE-2026-38698-AND-CVE-2026-38699&utm_source=rss&utm_medium=rss
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Inventory all IoT devices, specifically Wyze cameras, to identify those utilizing the vulnerable TUTK SDK.
      owner: IT Operations
      due: 48h
      evidence: Source identifies TUTK SDK v.3.1.10.0 through v.4.3.8.1 as the affected component.
  hunt_leads:
    - lead: Monitor network traffic for anomalous UDP volume or malformed packets directed toward port 32761 on IoT devices.
      technique_id: T1203
      data_needed:
        - Network flow logs or PCAP
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: CVE-2026-38698 vector involves sending crafted oversized AV packets to UDP port 32761.
  mitigation_plan:
    - priority: immediate
      action: Apply manufacturer-provided firmware updates for affected IoT hardware.
      owner: IT Operations
      addresses: CVE-2026-38698, CVE-2026-38699
      evidence: These vulnerabilities reside in the integrated TUTK SDK.
---

ThroughTek (TUTK) SDK versions 3.1.10.0 through 4.3.8.1 contain two distinct vulnerabilities: a heap overflow (CVE-2026-38698) and an out-of-bounds read (CVE-2026-38699). CVE-2026-38698 occurs within the tutk_packet_alloc function when processing an oversized AV packet sent to UDP port 32761, requiring an authenticated attacker. CVE-2026-38699 exists in the __Fill_ReadBuf function and can be triggered by a local attacker sending a UDP packet with an invalid payload offset. These SDK vulnerabilities affect various IoT products, including the Wyze Cam Pan. Proof-of-concept code has been publicly released.

## Impact

Successful exploitation of CVE-2026-38698 may result in memory corruption via heap overflow, potentially leading to arbitrary code execution. CVE-2026-38699 may cause memory access issues, likely resulting in service crashes or unauthorized memory exposure.

## Recommendation

- Identify IoT devices within the environment utilizing the affected TUTK SDK versions (3.1.10.0 to 4.3.8.1).
- Prioritize firmware updates from device manufacturers that incorporate patched versions of the TUTK SDK.
- Implement network segmentation to restrict access to IoT device communication ports, specifically UDP port 32761, from untrusted segments.
