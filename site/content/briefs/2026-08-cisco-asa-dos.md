---
title: Denial of Service Vulnerability in Cisco ASA and FTD
slug: 2026-08-cisco-asa-dos
description: A vulnerability in the web-based management interface of Cisco ASA and Secure Firewall Threat Defense allows an unauthenticated, remote attacker to trigger a device crash via crafted HTTP requests.
date: "2026-08-12T08:37:37Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:cisco:nexus_dashboard_fabric_controller:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - networking
  - security-appliance
vendors:
  - Cisco
products:
  - Adaptive Security Appliance
  - Secure Firewall Threat Defense
cves:
  - id: CVE-2024-20444
    cvss: 5.5
    epss: 0.00755
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-2755
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  mitigation_plan:
    - priority: immediate
      action: Patch Cisco ASA and FTD systems against CVE-2024-20444
      owner: IT Operations
      addresses: CVE-2024-20444
      evidence: Source advisory confirms the vulnerability and necessity of updates
---

Cisco has identified a vulnerability in the web-based management interface of the Adaptive Security Appliance (ASA) software and Secure Firewall Threat Defense (FTD) software. This flaw, tracked as CVE-2024-20444, allows an unauthenticated, remote attacker to perform a Denial of Service (DoS) attack. By sending specifically crafted HTTP requests to the targeted device, an attacker can cause the device to crash and subsequently reboot, leading to a temporary loss of network connectivity and security enforcement capabilities. This issue is significant for security operations as it targets the management plane of critical network infrastructure, potentially resulting in unauthorized service downtime. Defenders should prioritize patching affected systems to mitigate the risk of disruption to core security services.

## Impact

Successful exploitation results in a crash and automatic reboot of the affected Cisco ASA or FTD device. This impact leads to a total denial of network and security services provided by the appliance, effectively bypassing firewall rules and security policies for the duration of the outage. The target audience includes enterprises relying on Cisco perimeter security infrastructure for traffic control and threat mitigation.

## Recommendation

* Prioritize applying software updates provided by Cisco to address CVE-2024-20444 across all internet-facing and internal management interfaces.
* Restrict access to the web-based management interface of Cisco appliances to trusted management networks only, utilizing access control lists to prevent external reachability.
