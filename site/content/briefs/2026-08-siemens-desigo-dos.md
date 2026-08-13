---
title: Denial of Service Vulnerability in Siemens Desigo DXR and PXC Controllers
slug: 2026-08-siemens-desigo-dos
description: Siemens Desigo DXR and PXC controllers are vulnerable to a denial-of-service condition (CVE-2026-59693) triggered by malformed BACnet packets, requiring a manual device reboot.
date: "2026-08-13T16:51:58Z"
type: advisory
types:
  - advisory
severities:
  - low
vendors:
  - Siemens
products:
  - Desigo DXR2
  - Desigo PXC3
  - Desigo PXC4
  - Desigo PXC5.E003
  - Desigo PXC5.E24
  - Desigo PXC7
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: An attacker can exploit this issue by sending a malformed BACnet packet, causing the device to stop responding to BACnet queries.
    confidence_band: high
cves:
  - id: CVE-2026-59693
    cvss: 4.3
    epss: 0.00163
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-225-08
  - https://www.cve.org/CVERecord?id=CVE-2026-59693
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Patch affected Siemens Desigo controllers to the latest firmware versions
      owner: IT Operations
      due: 7d
      evidence: Vendor fix section of CISA advisory
  mitigation_plan:
    - priority: immediate
      action: Restrict BACnet protocol traffic via network firewalls and ensure devices are isolated from non-industrial networks
      owner: IT Operations
      addresses: CVE-2026-59693
      evidence: General Recommendations section of source
---

Siemens has disclosed a security vulnerability affecting various models of its Desigo DXR and PXC building automation controllers. The vulnerability, tracked as CVE-2026-59693, stems from an improper check for unusual or exceptional conditions within the device's BACnet protocol implementation. An unauthenticated attacker with network access to the controller can send a specifically crafted, malformed BACnet packet that causes the device to cease responding to legitimate network queries. This results in a denial-of-service (DoS) condition, impacting building management functions. Restoration of services requires a manual hardware reset or power cycle of the affected device. Siemens has released firmware updates for the impacted product lines and strongly recommends that operators transition to the patched versions to eliminate the risk. The vulnerability is rated with a CVSS 3.1 base score of 4.3 (Medium), reflecting the requirement for adjacent network access and the need for manual intervention to recover.

## Impact

The vulnerability affects critical infrastructure sectors including energy, healthcare, public health, commercial facilities, and manufacturing. Successful exploitation leads to a loss of availability for the targeted Desigo controllers, potentially disrupting facility environmental and automation controls. Because these devices are typically managed via local industrial networks, the impact is primarily felt by organizations operating in the physical security and facility management domains. There is no evidence of remote code execution or data exfiltration associated with this vulnerability.

## Recommendation

Prioritize patching of all identified Desigo DXR and PXC controllers listed in the affected products section. Given the requirement for manual intervention to restore service, operators should conduct a risk assessment before deployment to account for potential downtime during the maintenance cycle. Implement strict network segmentation to restrict BACnet traffic to authorized devices only and ensure controllers are not accessible from the public internet. Monitor industrial networks for anomalous BACnet traffic patterns that deviate from standard operational baselines.
