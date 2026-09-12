---
title: Cyclops Blink Modular Linux Implant Targeting Network-Edge Appliances
slug: 2026-09-cyclops-blink-linux
description: The IRON VIKING threat group has deployed an updated modular Cyclops Blink variant on Cisco Firewall Management Center devices, using SysV persistence and masquerading as a kernel thread to conduct reconnaissance and remote operations.
date: "2026-09-11T18:53:15Z"
lastmod: "2026-09-12T13:07:11Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - IRON VIKING
tags:
  - cyclops-blink
  - iron-viking
  - linux
  - modular-malware
  - network-edge
vendors:
  - Cisco
  - WatchGuard
products:
  - Firewall Management Center
  - Firebox
  - XTM
affected_os:
  - Linux
references:
  - https://www.sophos.com/en-us/blog/-eye-spy-cyclops-blink-returns-with-extended-capabilities
  - https://www.reddit.com/r/blueteamsec/comments/1weam99/eye_spy_cyclops_blink_returns_with_extended/
rules:
  - title: Detect Suspicious Process Masquerading as Kernel Thread
    description: Detects non-kernel processes masquerading as kworker threads by matching the common kworker naming convention applied to standard user-space binaries.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1036.004
    data_sources:
      - process_creation
      - linux
rules_count: 1
updates:
  - at: "2026-09-12T13:07:11Z"
    level: L1
    summary: new product
    sources:
      - reddit-blueteamsec
    source_urls:
      - https://www.reddit.com/r/blueteamsec/comments/1weam99/eye_spy_cyclops_blink_returns_with_extended/
---

In August 2026, researchers identified a sophisticated 64-bit Linux modular implant named 'timezone_check' operating on Cisco Firewall Management Center (FMC) appliances. Attributed to the Russia-based IRON VIKING (also known as Sandworm) threat group, this variant represents a significant evolution from the 2022 firmware-based Cyclops Blink implants. By leveraging standard System V (SysV) initialization scripts for persistence instead of vendor-specific firmware modifications, the malware achieves broader compatibility across Linux-based network-edge devices. 

The architecture centers on a 'controller' process that masquerades as a legitimate Linux kernel thread '[kworker/0:1]' to evade casual inspection. This controller coordinates five child-process worker modules that perform host reconnaissance, file exfiltration, arbitrary payload execution, network discovery, and packet surveillance. The ability to load and register new modules at runtime allows the threat actors to maintain persistent remote access and transform compromised network-edge appliances into versatile platforms for intelligence collection and lateral movement within sensitive management environments.

## Attack Chain

1. Initial infection via exploitation of undisclosed vulnerability on the network-edge appliance.
2. Deployment of the 64-bit ELF executable 'timezone_check' to the target system.
3. Execution of the malware which immediately initiates a masquerading process named '[kworker/0:1]' to hide in process listings.
4. Modification of Linux iptables (via libiptc or the iptables utility) to permit outbound TCP traffic on ports 43856 and 49172.
5. Establishment of persistence via standard SysV init scripts to ensure the implant survives system reboots.
6. Controller initialization, which synchronizes the shared status structure and IPC channels with five worker modules.
7. Regular execution of module 0x08 for host and network reconnaissance, including the potential theft of sensitive files like /etc/shadow.
8. Deployment of module 0x0F for C2-orchestrated file transfers and the execution of additional modular payloads to expand mission objectives.

## Impact

The compromise of network-edge appliances such as Cisco FMC provides attackers with deep visibility into internal network segments, access to administrative management interfaces, and the potential for intercepting traffic across critical segments. Successful exploitation allows for persistent intelligence collection, lateral movement into internal systems, and the ability to exfiltrate configurations and credentials from the device itself. Given the role of these appliances in securing infrastructure, the impact extends to a complete loss of confidentiality and integrity within the managed environment.

## Recommendation

* Hunt for the masquerading process name '[kworker/0:1]' in process listings, as legitimate kernel threads typically appear in brackets but are managed by the kernel, not as standalone ELF binaries.
* Monitor for unauthorized modifications to iptables rules, specifically those permitting traffic on non-standard ports 43856 and 49172.
* Deploy the Sigma rule below to detect suspicious process execution masquerading as kernel threads.
* Inspect persistent startup directories for non-standard SysV init scripts added without a clear administrative change record.
* Restrict outbound network access from internal infrastructure components to untrusted external IP addresses.
