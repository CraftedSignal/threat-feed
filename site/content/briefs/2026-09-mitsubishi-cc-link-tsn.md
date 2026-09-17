---
title: Mitsubishi Electric CC-Link IE TSN Communication Protocol Vulnerability
slug: 2026-09-mitsubishi-cc-link-tsn
description: A vulnerability in the Mitsubishi Electric CC-Link IE TSN Communication Protocol (CVE-2026-13584) allows network-adjacent attackers to disrupt control functions or tamper with data via specially crafted packets.
date: "2026-09-17T17:10:57Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - ics
  - ot
  - vulnerability
  - cve-2026-13584
vendors:
  - Mitsubishi Electric
products:
  - MELSEC MX Controller (all versions)
  - Master/local module (all versions)
  - CC-Link IE TSN interface board (all versions)
  - Motion module (all versions)
  - MELSEC iQ-L Series Motion Module (all versions)
  - Motion Control Board (all versions)
  - Block-type remote module (all versions)
  - Analog-Digital converter module (all versions)
  - Digital-Analog converter module (all versions)
  - CC-Link IE TSN compatible coupler (all versions)
  - FPGA module (all versions)
  - Tension meter (all versions)
  - AC Servo MELSERVO-J5 (all versions)
  - AC Servo MELSERVO-JET (all versions)
  - Liner Track System MTR-S series (all versions)
  - Inverter FR-A800/F800/E800 Series (all versions)
  - Industrial Robot CR800-D series (all versions)
  - CC-Link IE TSN expansion unit (all versions)
  - CC-Link IE TSN-CC-Link IE Field Network bridge module (all versions)
  - CC-Link IE TSN-AnyWireASLINK bridge module (all versions)
  - Energy Measuring Unit CC-Link IE TSN Communication Unit (all versions)
  - GOT3000 Series (all versions)
  - CC-Link IE TSN Communication Unit (all versions)
  - Motion Control Software (all versions)
  - CC-Link IE TSN Communication Software for Windows (all versions)
  - Analysis Support Software MELSOFT VIMA (all versions)
  - Master/Local module Designated communication LSI DeviceKit (all versions)
  - Remote Station Communication LSI with GbE-PHY (all versions)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Network Denial of Service
    evidence: Successful exploitation of this vulnerability could allow an attacker... to cause a denial-of-service (DoS) condition in the affected product by interfering with its control function.
    confidence_band: high
cves:
  - id: CVE-2026-13584
    epss: 0.00127
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-211-07
action_plan:
  priority: elevated
  owners:
    - SOC
    - OT Security
  mitigation_plan:
    - priority: immediate
      action: Restrict network access to affected industrial segments
      owner: OT Security
      addresses: CVE-2026-13584
      evidence: Source advises that exploitation requires access to the same network segment.
---

Mitsubishi Electric has identified a significant vulnerability (CVE-2026-13584) affecting a wide range of industrial automation products utilizing the CC-Link IE TSN communication protocol. This vulnerability exists in the protocol's handling of network traffic, specifically related to the timing of packet processing. An attacker with access to the same local network segment as the target device can leverage this flaw by injecting specially crafted packets under precise timing conditions.

If successful, the exploitation results in the interference of the device's primary control functions. This can manifest as unauthorized tampering with process communication data or the triggering of a Denial-of-Service (DoS) condition, potentially causing the industrial equipment to operate incorrectly or cease functionality entirely. Given the broad ecosystem of affected hardware, including motion modules, servos, inverters, and industrial controllers, this vulnerability poses a critical operational risk to facilities relying on these components for time-sensitive industrial control.

## Impact

The vulnerability impacts a vast array of Mitsubishi Electric industrial assets, including the MELSEC iQ series, GOT3000 HMI series, and various motor control units. Successful exploitation can lead to a complete loss of control over industrial processes, potentially leading to equipment damage, process shutdowns, or safety-related disruptions in production environments. Organizations utilizing these products within their Operational Technology (OT) networks are advised to restrict network access to affected controllers and implement strict network segmentation to mitigate the risk of unauthorized traffic reaching the CC-Link IE TSN network segment.

## Recommendation

- Implement strict network segmentation to ensure that only authorized devices have access to the CC-Link IE TSN network segment.
- Monitor for anomalous industrial network traffic patterns, specifically focusing on malformed or out-of-sequence packets directed at CC-Link IE TSN-enabled interfaces.
- Review the official Mitsubishi Electric security bulletin for specific patch availability or configuration hardening steps for each identified product model.
- Limit physical and logical access to the network infrastructure supporting these industrial assets to mitigate the requirement for local segment access.
