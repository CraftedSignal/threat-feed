---
title: Denial-of-Service Vulnerability in Rockwell Automation Logix Platforms
slug: 2026-09-rockwell-logix-dos
description: Rockwell Automation Logix controllers are vulnerable to a denial-of-service condition due to improper input length validation during CIP message processing, leading to major nonrecoverable faults.
date: "2026-09-01T17:11:02Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
tags:
  - industrial-control-systems
  - denial-of-service
  - cve-2026-9637
  - ot-security
vendors:
  - Rockwell Automation
products:
  - ControlLogix 5580 (<=V33, V34.011-V34.014, V35.011-V35.013, V36.011-V36.012)
  - CompactLogix 5380 (<=V33, V34.011-V34.014, V35.011-V35.013, V36.011-V36.012)
  - GuardLogix 5580 (<=V33, V34.011-V34.014, V35.011-V35.013, V36.011-V36.012)
  - Compact GuardLogix 5380 (<=V33, V34.011-V34.014, V35.011-V35.013, V36.011-V36.012)
cves:
  - id: CVE-2026-9637
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-244-03
  - https://www.cve.org/CVERecord?id=CVE-2026-9637
action_plan:
  priority: elevated
  owners:
    - OT Security
    - IT Operations
  mitigation_plan:
    - priority: immediate
      action: Upgrade firmware to V37.011, 34.015, 35.014, or 36.013
      owner: OT Engineering
      addresses: CVE-2026-9637
      evidence: Vendor fix provided by Rockwell Automation
---

Rockwell Automation has identified a critical denial-of-service (DoS) vulnerability, CVE-2026-9637, affecting multiple versions of the Logix platform, including the ControlLogix 5580, CompactLogix 5380, GuardLogix 5580, and Compact GuardLogix 5380 series. The vulnerability stems from improper validation of input length within the Common Industrial Protocol (CIP) message processing logic. 

When a specifically crafted CIP message is sent to an affected device, it triggers an improper memory buffer operation, resulting in a Major Nonrecoverable Fault (MNRF). This state forces the controller to stop its primary operations, requiring a physical power cycle to restore functionality. Given that these devices are widely deployed in the Critical Manufacturing sector, a successful exploitation could result in significant operational disruption. There is no evidence of active exploitation in the wild as of this advisory's release, but organizations should prioritize firmware updates to the recommended versions.

## Impact

Successful exploitation of CVE-2026-9637 causes an immediate denial-of-service on the affected industrial controllers. Because the fault triggered is a Major Nonrecoverable Fault (MNRF), the controller enters a stop state and cannot be recovered remotely, necessitating manual technician intervention to perform a power cycle. This impacts process availability in manufacturing environments and requires downtime for remediation.

## Recommendation

* Apply the firmware updates provided by Rockwell Automation to all affected controllers: update to V37.011, V34.015, V35.014, or V36.013 depending on your current version (CVE-2026-9637).
* Minimize network exposure by isolating industrial control system networks from enterprise networks and the internet.
* Implement defense-in-depth strategies to protect control system devices as outlined in CISA ICS-TIP-12-146-01B.
* If remote access to the OT environment is required, use secure VPNs that are patched and monitored for vulnerabilities.
