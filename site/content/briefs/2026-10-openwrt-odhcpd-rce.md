---
brief_id: brief-2026-10-22-openwrt-odhcpd-rce
event_id: brief-2026-10-22-openwrt-odhcpd-rce
revision: 1
activity_at: "2026-10-22T07:02:17Z"
title: 'OpenWrt odhcpd: Stack-based buffer overflow (CVE-2026-53921)'
slug: 2026-10-openwrt-odhcpd-rce
description: An unauthenticated remote code execution vulnerability (CVE-2026-53921) in the OpenWrt DHCPv6 server component odhcpd allows attackers to execute code with root privileges via crafted DHCPv6 requests.
date: "2026-10-22T07:02:17Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: very likely
qa_status:
  verdict: pass
  validation_status: Verified CVE details and affected versions against the provided advisory.
tags:
  - remote-code-execution
  - buffer-overflow
  - network-security
  - dhcpv6
vendors:
  - OpenWrt
products:
  - odhcpd (< 24.10.8)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A remote, unauthenticated attacker can send a specially crafted DHCPv6 REQUEST packet to trigger memory corruption, potentially leading to arbitrary code execution with root privileges.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1211
    technique_name: Exploitation for Defense Evasion
    evidence: Because odhcpd executes with root privileges, successful exploitation may result in complete device compromise.
    confidence_band: high
cves:
  - id: CVE-2026-53921
    kev_status: unknown
references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-0XBLACKASH-CVE-2026-53921
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-0XBLACKASH-CVE-2026-53921&utm_source=rss&utm_medium=rss
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Network Security
  immediate_actions:
    - action: Inventory all OpenWrt devices and verify current odhcpd/firmware versions.
      owner: IT Operations
      due: 24h
      evidence: Source identifies odhcpd version < 24.10.8 as vulnerable.
  mitigation_plan:
    - priority: immediate
      action: Upgrade OpenWrt devices to 24.10.8 or 25.12.5.
      owner: IT Operations
      addresses: CVE-2026-53921
      evidence: Fixed versions provided in source advisory.
---

CVE-2026-53921 is a stack-based buffer overflow vulnerability in the OpenWrt DHCPv6 server component, `odhcpd`. The vulnerability allows an unauthenticated remote attacker to send a specially crafted DHCPv6 REQUEST packet to the server, resulting in memory corruption. This can lead to arbitrary code execution with root privileges or a Denial of Service (DoS) condition. The vulnerability has been confirmed with a CVSS score of 9.8.

## Impact

Successful exploitation allows for unauthenticated remote code execution with root-level privileges on affected OpenWrt devices. This grants attackers full control over the compromised network device, potentially facilitating lateral movement within the network, traffic interception, or permanent device compromise.

## Recommendation

- Upgrade OpenWrt devices to version 24.10.8 or 25.12.5 and later to incorporate the security patch.
- Implement network segmentation to restrict DHCPv6 traffic exposure to only authorized and trusted network segments.
- Prioritize patching for internet-facing gateways or devices providing DHCPv6 services to untrusted network zones.
