---
title: Critical Out-of-Bounds Write in lwIP MQTT Client
slug: 2026-09-lwip-mqtt-rce
description: An out-of-bounds write vulnerability (CVE-2026-87121) in the lwIP TCP/IP Stack MQTT client allows unauthenticated remote attackers to achieve full code execution on affected devices.
date: "2026-09-22T16:47:26Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:lwip:lwip:2.0.1:*:*:*:*:*:*:*
  - cpe:2.3:a:lwip:lwip:2.2.1:*:*:*:*:*:*:*
vendors:
  - lwIP
products:
  - lwIP TCP/IP Stack MQTT Client Application (2.0.1 - 2.2.1)
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-265-01
  - https://www.cve.org/CVERecord?id=CVE-2026-87121
  - https://savannah.nongnu.org/projects/lwip
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - OT Security
  immediate_actions:
    - action: Patch or mitigate vulnerable lwIP MQTT client implementations
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-87121 remediation guidance from CISA
  mitigation_plan:
    - priority: immediate
      action: Isolate MQTT-enabled devices from the internet and restricted networks
      owner: OT Security
      addresses: CVE-2026-87121
      evidence: Recommended practices section of ICSA-26-265-01
---

The lwIP TCP/IP stack contains a critical out-of-bounds write vulnerability in its MQTT client implementation, tracked as CVE-2026-87121. This flaw affects versions 2.0.1 through 2.2.1 of the MQTT client application. The vulnerability allows an unauthenticated, remote attacker to trigger a memory corruption condition by sending specially crafted MQTT packets, potentially leading to full code execution on the underlying device. Given that the lwIP stack is commonly embedded in resource-constrained IoT, industrial, and embedded devices across critical infrastructure sectors such as energy, water, and manufacturing, this vulnerability presents a high risk for wide-scale exploitation. Defenders should prioritize identifying instances of the affected stack within their OT and IoT environments and apply the upstream patch associated with commit f89407ea711879c04d91c92b35d67be78bbaf0f1.

## Impact

Successful exploitation of CVE-2026-87121 allows an unauthenticated remote attacker to gain full code execution on the device, resulting in a complete compromise of the affected asset. This could lead to unauthorized control of industrial processes, exfiltration of sensitive telemetry data, or deployment of further payloads. The vulnerability is rated with a CVSS score of 9.8 (Critical) due to its remote, unauthenticated, and low-complexity exploitation requirements. Sectors relying on embedded lwIP stacks, particularly those in critical infrastructure, face significant operational and security risks if devices are exposed to untrusted networks.

## Recommendation

* Immediately identify all systems utilizing the lwIP TCP/IP Stack MQTT client version 2.0.1 through 2.2.1.
* Apply the official vendor fix available in the lwIP project repository, specifically the commit f89407ea711879c04d91c92b35d67be78bbaf0f1.
* Isolate vulnerable devices from the public internet by placing them behind firewalls or within dedicated, restricted network segments.
* Implement network-level ingress filtering to restrict MQTT traffic (typically port 1883 or 8883) to authorized communication partners only.
* Enable logging for MQTT traffic patterns to detect anomalies indicative of malformed packet transmission.
