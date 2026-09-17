---
title: Improper Input Validation in Schneider Electric Modicon M340 Modules
slug: 2026-09-modicon-m340-dos
description: An improper input validation vulnerability (CVE-2025-6625) in Schneider Electric Modicon M340 controllers and communication modules allows unauthenticated attackers to cause a denial-of-service via crafted FTP commands.
date: "2026-09-17T17:11:59Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - ics
  - cve-2025-6625
  - denial-of-service
  - schneider-electric
vendors:
  - Schneider Electric
products:
  - Modicon M340 (all versions prior to SV3.70)
  - BMXNOE0100 (< 3.60)
  - BMXNOE0110 (< 6.80)
  - BMXNOR0200H (< SV1.7_IR27)
  - BMXNGD0100
  - BMXNOC0401
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Network Denial of Service
    evidence: Improper Input Validation vulnerability exists that could cause a Denial Of Service when specific crafted FTP command is sent to the device.
    confidence_band: high
cves:
  - id: CVE-2025-6625
    cvss: 7.5
    epss: 0.00476
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-260-04
  - https://www.cve.org/CVERecord?id=CVE-2025-6625
action_plan:
  priority: elevated
  owners:
    - OT Security
    - Network Operations
  immediate_actions:
    - action: Audit network perimeter for exposed TCP port 21 on Modicon M340 devices.
      owner: Network Operations
      due: 24h
      evidence: 'Mitigation: Setup network segmentation and implement a firewall to block all unauthorized access to ports 21/FTP.'
  mitigation_plan:
    - priority: immediate
      action: Disable FTP service on affected modules.
      owner: OT Security
      addresses: CVE-2025-6625
      evidence: FTP service is disabled by default. Ensure to disable FTP service when not in use.
---

Schneider Electric has disclosed a vulnerability (CVE-2025-6625) affecting multiple Modicon M340 controller and communication modules. The flaw stems from improper input validation in the device's FTP service, which is susceptible to denial-of-service (DoS) attacks. An unauthenticated remote attacker can send a specially crafted FTP command to an affected device, causing it to crash or become unresponsive, leading to operational unavailability. 

The vulnerability impacts a wide range of modules, including the BMXNOR0200H, BMXNGD0100, BMXNOC0401, BMXNOE0100, and BMXNOE0110, as well as the core M340 controller firmware. Given the deployment of these devices in critical infrastructure sectors like energy, water and wastewater, and manufacturing, the impact of service disruption is significant. Schneider Electric has released firmware updates for several modules and recommends disabling FTP services or implementing strict network segmentation if patching is not immediately feasible.

## Impact

Successful exploitation results in a Denial of Service (DoS), rendering the affected industrial controller unavailable. This poses a high risk to critical infrastructure sectors - including energy, water, wastewater, and chemical manufacturing - where device uptime is essential for safe operations. There are no reports of remote code execution or data exfiltration associated with this specific vulnerability.

## Recommendation

* Apply the vendor-provided firmware updates immediately to affected modules:
 * Update BMXNOE0100 to version 3.60 or later.
 * Update BMXNOE0110 to version 6.80 or later.
 * Update Modicon M340 controller firmware to version SV3.70 or later.
 * Update BMXNOR0200H to version SV1.7 IR27 or later.
* Disable the FTP service on all Modicon M340 modules if it is not required for operational tasks.
* Implement strict network segmentation and firewall rules to block unauthorized access to TCP port 21 on all industrial devices.
* Require the use of VPNs for any necessary remote maintenance or monitoring access to the control network.
* Ensure controllers are kept in locked cabinets and are not left in "Program" mode during standard operation.
