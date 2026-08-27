---
title: Denial of Service Vulnerability in Mitsubishi Electric CNC Series
slug: 2026-08-mitsubishi-cnc-dos
description: An out-of-bounds read vulnerability (CVE-2025-2399) in Mitsubishi Electric CNC Series controllers allows remote attackers to trigger a denial-of-service condition via crafted packets sent to TCP port 683.
date: "2026-08-27T16:06:18Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - ics
  - dos
  - industrial-control-systems
  - critical-infrastructure
  - cve-2025-2399
vendors:
  - Mitsubishi Electric
products:
  - M800VW
  - M800VS
  - M80V
  - M80VW
  - M800W
  - M800S
  - M80
  - M80W
  - E80
  - C80
  - M750VW
  - M730VW
  - M720VW
  - M750VS
  - M730VS
  - M720VS
  - M70V
  - E70
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-078-05
  - https://www.cve.org/CVERecord?id=CVE-2025-2399
  - https://www.mitsubishielectric.com/fa/download/index.html
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - OT Security
  immediate_actions:
    - action: Restrict network access to TCP port 683 for all listed CNC devices
      owner: OT Security
      due: 24h
      evidence: CISA advisory mitigation recommendation
  mitigation_plan:
    - priority: immediate
      action: Patch firmware to designated versions
      owner: IT Operations
      addresses: CVE-2025-2399
      evidence: CISA advisory remediation section
---

Mitsubishi Electric has disclosed a vulnerability (CVE-2025-2399) affecting multiple versions of its CNC Series controllers, including the M800V, M80V, M800, M80, E80, C80, and M70 series. The vulnerability is rooted in improper validation of indices, positions, or offsets (CWE-1285) within the input processing logic of the affected devices. 

By sending specially crafted packets to TCP port 683, a remote attacker can induce an out-of-bounds read, resulting in a denial-of-service (DoS) condition. This vulnerability poses a risk to critical manufacturing environments where these CNC controllers are deployed. Defenders should focus on isolating affected hardware from untrusted networks and restricting access to TCP port 683. Patches are available from Mitsubishi Electric, and organizations should prioritize updates to the specified versions (BC, FN, or LK, depending on the product series) or apply the recommended IP filtering and network segmentation mitigations.

## Impact

The successful exploitation of CVE-2025-2399 results in a denial-of-service, which in an industrial manufacturing context can lead to unplanned downtime, loss of production, and disruption of automated machining processes. The vulnerability is rated with a CVSS 3.1 score of 5.9 (Medium), reflecting that while exploitation is remote, it requires specific technical craft to trigger the DoS condition. The affected devices are deployed globally in the critical manufacturing sector.

## Recommendation

- Apply the vendor-provided firmware updates (version BC, FN, or LK) appropriate for the specific CNC controller model.
- Isolate CNC controller networks from the enterprise network using firewalls or VPNs to prevent unauthorized access to TCP port 683.
- Implement IP address filtering on the affected controllers using the manufacturer's built-in functions to restrict communication to known-authorized endpoints.
- Restrict physical access to CNC hardware and connected network infrastructure.
- Deploy network intrusion detection systems to alert on abnormal traffic patterns directed at TCP port 683.
