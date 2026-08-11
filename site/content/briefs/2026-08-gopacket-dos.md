---
title: CVE-2026-65819 Denial of Service in gopacket DecodingLayerParser
slug: 2026-08-gopacket-dos
description: An unauthenticated remote attacker can trigger a denial-of-service condition by sending crafted network packets that cause multiple layer decoders in the gopacket library to panic due to out-of-bounds access and integer underflow.
date: "2026-08-11T10:32:02Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - denial-of-service
  - vulnerability
  - network-security
vendors:
  - Google
products:
  - gopacket
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Network Denial of Service
    evidence: An unauthenticated remote attacker can trigger a panic in multiple layer decoders, resulting in a denial-of-service (DoS) condition.
    confidence_band: high
cves:
  - id: CVE-2026-65819
    cvss: 7.5
    epss: 0.00366
references:
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-65819
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Inventory all software dependencies using gopacket for vulnerability identification
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-65819 vulnerability advisory
  mitigation_plan:
    - priority: immediate
      action: Update gopacket library versions to the patched release
      owner: IT Operations
      addresses: CVE-2026-65819
      evidence: MSRC Security Update Guide
---

CVE-2026-65819 is a vulnerability in the popular Go-based networking library, gopacket. The issue exists within the DecodingLayerParser component, which is responsible for high-speed packet parsing. The vulnerability allows an unauthenticated remote attacker to craft and transmit specific network packets that trigger integer underflow and out-of-bounds memory read conditions. When processed by the library, these malformed packets cause multiple layer decoders to panic, leading to an immediate crash of the application using the library. This impact is significant for network security appliances, packet capture tools, and monitoring software that rely on gopacket for traffic analysis. Because the vulnerability results in a process-level panic, it provides a reliable vector for remote denial-of-service (DoS) against any service utilizing unpatched versions of this library.

## Impact

Successful exploitation results in the abnormal termination of the target process, leading to a denial-of-service condition. This affects any infrastructure component, security monitor, or network traffic analyzer that utilizes the gopacket library to parse incoming traffic. Depending on the architecture, this could blind security monitoring capabilities or drop network traffic entirely.

## Recommendation

Prioritized, concrete actions for detection engineering teams:
- Identify all internal software and third-party tools within the environment that utilize the gopacket library as a dependency.
- Review vendor security advisories for updates to products utilizing gopacket and schedule immediate patching cycles.
- Implement network-level monitoring to identify malformed traffic flows if a specific application or service starts experiencing recurring, unexplained crashes.
- Prioritize patching of internet-facing network appliances that utilize gopacket for deep packet inspection or traffic telemetry collection.
