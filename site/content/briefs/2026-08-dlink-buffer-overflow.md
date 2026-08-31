---
title: Remote Stack-Based Buffer Overflow in D-Link DIR-825M
slug: 2026-08-dlink-buffer-overflow
description: A critical stack-based buffer overflow vulnerability in D-Link DIR-825M firmware allows unauthenticated remote attackers to achieve code execution via the /boafrm/formDiskFormat endpoint.
date: "2026-08-31T01:12:58Z"
lastmod: "2026-08-31T01:13:06Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:h:dlink:dir-825m:1.1.8:*:*:*:*:*:*:*
tags:
  - remote-code-execution
  - buffer-overflow
  - network-security
vendors:
  - D-Link
products:
  - DIR-825M (1.1.8)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The attack can be executed remotely.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1211
    technique_name: Exploitation for Defense Evasion
    evidence: This manipulation of the argument fota_url causes stack-based buffer overflow.
    confidence_band: high
cves:
  - id: CVE-2026-82592
    cvss: 9.9
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-82592
  - https://nvd.nist.gov/vuln/detail/CVE-2026-82593
rules:
  - title: Detects CVE-2026-82592 Exploitation - Malicious POST to Disk Formatting Endpoint
    description: Detects exploitation attempts against CVE-2026-82592 by monitoring for POST requests to the /boafrm/formDiskFormat endpoint with potentially malicious partition parameters.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Restrict external access to device management interfaces.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-82592 is remotely exploitable.
  hunt_leads:
    - lead: Search web logs for suspicious strings in the partition parameter of the /boafrm/formDiskFormat endpoint.
      technique_id: T1190
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: CVE-2026-82592 vulnerability details.
  mitigation_plan:
    - priority: immediate
      action: Disable remote web management on vulnerable D-Link DIR-825M devices.
      owner: IT Operations
      addresses: CVE-2026-82592
      evidence: Public exploit available.
updates:
  - at: "2026-08-31T01:13:06Z"
    level: L2
    summary: added coverage for DIR-825M (1.1.8)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-82593
---

D-Link DIR-825M firmware version 1.1.8 contains a critical stack-based buffer overflow vulnerability identified as CVE-2026-82592. The vulnerability is located within the sub_46725C function of the Disk Formatting Handler component, specifically triggered through the /boafrm/formDiskFormat endpoint. By sending a maliciously crafted HTTP request containing an overly long 'partition' argument, an unauthenticated remote attacker can corrupt the stack, potentially leading to arbitrary code execution on the affected router. The exploit is currently public, significantly increasing the risk of exploitation by threat actors targeting small office/home office (SOHO) network infrastructure.

## Impact

Successful exploitation of this vulnerability allows unauthenticated remote attackers to gain full control over the affected D-Link DIR-825M router. This can lead to complete device compromise, unauthorized network access, interception of traffic, and persistence within the victim's network. Given that these devices are typically internet-facing, the risk of widespread automated exploitation is high.

## Recommendation

* Immediately restrict access to the web management interface of the D-Link DIR-825M to trusted internal IP addresses only.
* Disable remote management features on all exposed D-Link devices to prevent unauthenticated access to the /boafrm/formDiskFormat endpoint.
* Monitor network traffic for HTTP POST requests directed at the /boafrm/formDiskFormat path, particularly those containing suspicious strings or excessive length in the 'partition' parameter.
* Check for firmware updates from the vendor; if no patch is available, replace the device or isolate it from the public internet.
