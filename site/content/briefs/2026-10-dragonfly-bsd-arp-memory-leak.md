---
title: Kernel Memory Disclosure in DragonFly BSD via ARP
slug: 2026-10-dragonfly-bsd-arp-memory-leak
description: CVE-2026-110912 allows an unauthenticated attacker on a local L2 network to disclose kernel heap and stack memory by sending malformed ARP requests with oversized length fields.
date: "2026-10-15T08:57:37Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:o:dragonflybsd:dragonfly_bsd:*:*:*:*:*:*:*:*
tags:
  - kernel-vulnerability
  - memory-disclosure
  - arp
  - dragonfly-bsd
vendors:
  - DragonFly BSD Project
products:
  - DragonFly BSD (all releases including 6.4.2)
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1592
    technique_name: Gather Victim Host Information
    evidence: Unauthenticated remote kernel heap and stack memory disclosure in DragonFly BSD via ARP.
    confidence_band: high
cves:
  - id: CVE-2026-110912
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-110912
  - https://github.com/DragonFlyBSD/DragonFlyBSD/commit/4bb22ffcf2e9fb44995fbfd9945194afc87fb182
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Network Engineering
  immediate_actions:
    - action: Patch DragonFly BSD kernel using the provided upstream commit
      owner: IT Operations
      due: 48h
      evidence: 'Upstream fix: 4bb22ffcf2e9fb44995fbfd9945194afc87fb182'
  mitigation_plan:
    - priority: immediate
      action: Monitor network traffic for ARP packets with non-standard address length fields
      owner: Network Engineering
      addresses: CVE-2026-110912
      evidence: PoC uses ar_hln/ar_pln manipulation
---

CVE-2026-110912 is an unauthenticated remote kernel heap and stack memory disclosure vulnerability in DragonFly BSD. The vulnerability exists within the ARP implementation in `sys/netinet/if_ether.c`, specifically in the `arpintr()` and `in_arpreply()` functions. The kernel fails to validate the hardware address length (ar_hln) and protocol address length (ar_pln) fields of incoming ARP packets.

An attacker on the same local L2 segment can craft an ARP request specifying larger-than-expected length fields. When `in_arpreply()` processes these packets, it uses the attacker-controlled values as lengths for `memcpy()`, causing the kernel to copy data from adjacent heap or stack memory into the ARP reply. This allows an attacker to leak sensitive kernel memory, including KASLR-defeating pointers and return addresses. The vulnerability has been present since the initial 2003 code import and remains unpatched in all tagged releases as of October 2026, despite a fix existing in the master branch.

## Attack Chain

1. Attacker identifies a target host on the same L2 network segment.
2. Attacker crafts a custom ARP REQUEST packet using a tool like Scapy.
3. Attacker modifies the ARP header fields `ar_hln` (hardware address length) or `ar_pln` (protocol address length) to values exceeding the legitimate 6 (MAC) and 4 (IPv4) bytes respectively.
4. Attacker transmits the malformed ARP REQUEST to the victim host.
5. The victim's kernel (`arpintr()`) fails to validate the address length fields and proceeds to `in_arpreply()`.
6. The `in_arpreply()` function performs an out-of-bounds `memcpy()` of kernel memory based on the attacker's requested lengths.
7. The leaked kernel memory is encapsulated into an ARP REPLY packet and transmitted back to the attacker.
8. Attacker receives the packet and parses the OOB data to extract kernel pointers, facilitating the bypass of KASLR.

## Impact

Successful exploitation results in the disclosure of sensitive kernel memory. An attacker can recover kernel `.text` return addresses and KVA pointers, effectively defeating Kernel Address Space Layout Randomization (KASLR). This information leakage serves as a critical prerequisite for chaining further exploits to achieve arbitrary code execution or privilege escalation. Every release of DragonFly BSD is affected, and the attack is undetectable to the host system.

## Recommendation

1. Monitor local network segments for ARP packets with non-standard `ar_hln` or `ar_pln` values using network-based intrusion detection systems.
2. Apply the upstream patch from commit `4bb22ffcf2e9fb44995fbfd9945194afc87fb182` to all custom builds, as no official tagged release currently includes the fix.
3. Implement strict ARP packet filtering or validation at the L2 switch level where possible to reject packets with invalid hardware or protocol address lengths.
