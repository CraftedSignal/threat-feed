---
brief_id: brief-2026-11-02-videostrong-backdoor
event_id: brief-2026-11-02-videostrong-backdoor
revision: 1
activity_at: "2026-11-02T17:48:56Z"
title: Videostrong Android device firmware backdoor (x.cpe)
slug: 2026-11-videostrong-backdoor
description: Google disrupted a botnet of over 1.3 million Android devices, including TV set-top boxes, found to contain a persistent firmware-level backdoor intentionally installed by manufacturer Videostrong.
date: "2026-11-02T17:48:56Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - Videostrong
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: D
  credibility: "3"
  rating: D3
  likelihood: roughly even chance
tags:
  - supply-chain
  - botnet
  - android
  - firmware
  - residential-proxy
vendors:
  - Videostrong
products:
  - Android TV set-top boxes
  - Telehealth devices
  - Karaoke machines
  - Digital signage
affected_os:
  - Android
references:
  - https://thehackernews.com/2026/11/google-disrupts-13-million-device.html
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Identify and isolate all Videostrong and MECOOL-branded Android devices currently connected to the corporate network.
      owner: SOC
      due: 24h
      evidence: Synthient and Plume reports identified these models as containing the x.cpe backdoor.
  hunt_leads:
    - lead: Identify abnormal egress traffic patterns characteristic of residential proxy nodes originating from IoT device IP ranges.
      technique_id: T1071.001
      data_needed:
        - Firewall or NetFlow logs from segments housing IoT devices
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Most of the criminals modules turned the boxes into residential proxies or sold their spare bandwidth.
  mitigation_plan:
    - priority: immediate
      action: Replace all identified Videostrong-manufactured devices.
      owner: IT Operations
      addresses: x.cpe firmware backdoor
      evidence: Cleanup needs vendor action, platform protection or replacement of the device.
---

Google identified and disrupted a global botnet consisting of over 1.3 million infected Android devices, primarily TV set-top boxes, but also including telehealth devices, karaoke machines, and digital signage. The operation involved a persistent backdoor named x.cpe, which is embedded directly into the device firmware with system-level privileges. Google has confirmed that the manufacturer, Videostrong, intentionally implemented this backdoor, which was used to facilitate ad fraud and establish residential proxy networks. The backdoor can disable Google Play Protect, execute arbitrary commands, capture screens, and exfiltrate system data. Due to its firmware-level integration and use of manufacturer-signed system apps, the backdoor persists across factory resets.

## Attack Chain
1. Manufacturing: Videostrong embeds the x.cpe backdoor into device firmware during the production process.
2. Initial Access: The backdoor is pre-installed on devices distributed to consumers and organizations.
3. Evasion: Upon boot, the backdoor disables Google Play Protect to facilitate silent installation of malicious modules.
4. Command and Control: The backdoor contacts C2 servers, passing system information and awaiting instructions.
5. Exploitation: Remote operators deploy modules to the device, enabling residential proxy services or ad fraud operations.
6. Exfiltration: Operators capture screen content, keystrokes, and account details through remote shells or screen scraping.

## Impact
Over 1.3 million devices were confirmed to be part of the botnet, with infections detected across 206 models. The backdoor provides remote operators with full system access, allowing for the misuse of home internet bandwidth for residential proxy networks and unauthorized ad generation. The backdoor poses a persistent risk to corporate networks where these devices are connected, potentially serving as a pivot point.

## Recommendation
- Inventory all Android TV boxes and similar consumer IoT devices within your environment, specifically identifying those manufactured by or rebranded from Videostrong (e.g., MECOOL).
- Immediately isolate identified consumer Android devices from sensitive network segments or corporate infrastructure.
- Prioritize the replacement of devices identified as potentially infected, as firmware-level remediation is not feasible for the end-user.
- Implement network-level egress filtering to block traffic to known botnet control domains and IPs used by the x.cpe infrastructure.
- Treat all unmanaged consumer smart devices on home networks as untrusted; enforce the use of VPNs or managed endpoints for all corporate remote access.
