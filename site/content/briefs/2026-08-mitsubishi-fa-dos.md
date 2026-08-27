---
title: Denial of Service Vulnerability in Mitsubishi Electric FA Products
slug: 2026-08-mitsubishi-fa-dos
description: A vulnerability in the Ethernet function of multiple Mitsubishi Electric factory automation products allows remote attackers to trigger a denial-of-service condition via specially crafted UDP packets.
date: "2026-08-27T16:05:55Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - industrial-control-systems
  - denial-of-service
  - cve-2025-3511
vendors:
  - Mitsubishi Electric
products:
  - CC-Link IE TSN Remote I/O module (<=09)
  - CC-Link IE TSN Analog-Digital Converter module (<=07)
  - CC-Link IE TSN Digital-Analog Converter module (<=07)
  - CC-Link IE TSN FPGA module (01)
  - CC-Link IE TSN Remote Station Communication LSI CP620 (<=1.08J)
  - MELSEC iQ-R Series CC-Link IE TSN Master/Local Module (<=26)
  - MELSEC iQ-R Series Ethernet Interface Module (<=85)
  - CC-Link IE TSN master/local Station Communication LSI CP610 (<=05)
  - MELSEC iQ-F Series FX5 CC-Link IE TSN Master/Local Module (<=1.020)
  - MELSEC iQ-F Series FX5 Ethernet Module (<=1.200)
  - MELSEC iQ-F Series FX5-ENET/IP Ethernet Module (<=1.106)
  - MELSEC iQ-R Series CPU module (Network Part) (<=85)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Network Denial of Service
    evidence: This vulnerability could allow a remote attacker to cause a denial-of-service (DoS) condition by sending a specially crafted UDP packet.
    confidence_band: high
cves:
  - id: CVE-2025-3511
    cvss: 7.5
    epss: 0.00876
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-25-128-03
  - https://www.cve.org/CVERecord?id=CVE-2025-3511
action_plan:
  priority: elevated
  owners:
    - OT Security
    - Network Operations
  immediate_actions:
    - action: Inventory OT assets and identify affected Mitsubishi Electric modules.
      owner: OT Security
      due: 72h
      evidence: Advisory lists multiple affected series and firmware versions.
  mitigation_plan:
    - priority: immediate
      action: Isolate vulnerable controllers behind firewall/segmentation.
      owner: Network Operations
      addresses: CVE-2025-3511
      evidence: Advisory notes the attack is network-based via UDP.
---

Mitsubishi Electric has disclosed a high-severity vulnerability (CVE-2025-3511) affecting a wide array of Factory Automation (FA) products, including CC-Link IE TSN modules, MELSEC iQ-R series, and MELSEC iQ-F series controllers. The issue stems from Improper Validation of Specified Quantity in Input (CWE-1284) within the devices' Ethernet communication stack. By sending a specially crafted UDP packet to an affected device, a remote, unauthenticated attacker can induce a denial-of-service (DoS) condition, communication timeouts, or significant latency. Depending on the specific product, recovery requires a system reset or the resumption of valid UDP traffic. Given the deployment of these industrial control components within the critical manufacturing sector, this vulnerability poses a risk to operational availability and process continuity. Defenders should identify vulnerable assets within their OT networks and apply vendor-supplied firmware updates where available.

## Impact

The vulnerability impacts industrial control system infrastructure globally within the critical manufacturing sector. Successful exploitation results in a loss of network communication for critical I/O modules, CPUs, and interface modules. In many cases, a hardware reset is required to restore normal operations, which could lead to unplanned downtime and disruption of manufacturing processes.

## Recommendation

- Identify all affected Mitsubishi Electric FA hardware using the provided product list and ensure internal inventory reflects the specified vulnerable firmware versions.
- Implement network segmentation to isolate industrial Ethernet traffic, restricting access to these devices from untrusted network segments.
- Monitor for anomalous UDP traffic patterns originating from unauthorized sources directed toward industrial Ethernet interfaces.
- Prioritize firmware updates as provided by Mitsubishi Electric to address CVE-2025-3511 across the entire affected product line.
