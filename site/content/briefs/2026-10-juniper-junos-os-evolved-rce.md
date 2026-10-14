---
title: OS Command Injection in Juniper Junos OS Evolved TACACS
slug: 2026-10-juniper-junos-os-evolved-rce
description: An OS command injection vulnerability in the TACACS component of Juniper Junos OS Evolved allows authenticated, low-privileged users to achieve root-level code execution.
date: "2026-10-14T18:33:00Z"
lastmod: "2026-10-14T18:40:30Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:o:juniper:junos_os_evolved:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - cve
  - network-security
vendors:
  - Juniper Networks
products:
  - Junos OS Evolved
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: An OS Command Injection vulnerability in TACACS of Juniper Networks Junos OS Evolved allows a low-privileged TACACS+-authenticated user to execute commands with root privileges.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: The flaw allows a low-privileged, TACACS+-authenticated user to execute arbitrary commands with root-level privileges.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: An authenticated network attacker can exploit this flaw... potentially leading to... arbitrary code execution with root-level privileges.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated attacker on the management LAN can execute commands as root via crafted DHCP response.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Network Denial of Service
    evidence: A Reachable Assertion vulnerability in the na-grpcd process of Juniper Networks Junos OS Evolved allows a remote unauthenticated attacker to cause a denial of service.
    confidence_band: high
cves:
  - id: CVE-2026-102031
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-102031
  - https://nvd.nist.gov/vuln/detail/CVE-2026-101965
  - https://nvd.nist.gov/vuln/detail/CVE-2026-101967
  - https://nvd.nist.gov/vuln/detail/CVE-2026-102012
  - https://nvd.nist.gov/vuln/detail/CVE-2026-102068
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Network Security
  immediate_actions:
    - action: Patch Junos OS Evolved firmware to versions addressing CVE-2026-102031
      owner: IT Operations
      due: 24h
      evidence: NVD vulnerability disclosure
  mitigation_plan:
    - priority: immediate
      action: Disable periodic TACACS+ authorization-refresh
      owner: Network Security
      addresses: CVE-2026-102031
      evidence: The flaw allows a low-privileged... user to execute commands... when periodic TACACS+ authorization-refresh is enabled.
updates:
  - at: "2026-10-14T18:36:29Z"
    level: L2
    summary: added coverage for Junos OS Evolved
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-101965
  - at: "2026-10-14T18:36:39Z"
    level: L2
    summary: added coverage for Junos OS Evolved
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-101967
  - at: "2026-10-14T18:37:04Z"
    level: L1
    summary: added coverage for Junos OS Evolved
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-102012
  - at: "2026-10-14T18:40:30Z"
    level: L1
    summary: added coverage for Junos OS Evolved
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-102068
---

A critical OS command injection vulnerability (CVE-2026-102031) has been identified in the TACACS component of Juniper Networks Junos OS Evolved. This vulnerability allows an attacker who has successfully authenticated via TACACS+ to execute arbitrary operating system commands with root privileges. The exploitation vector is contingent on the device having the periodic TACACS+ authorization-refresh feature enabled. 

Because this vulnerability bypasses standard privilege restrictions for authenticated users, it represents a significant risk for lateral movement, persistent configuration modification, and full system compromise. Detection and mitigation should focus on identifying unauthorized command execution patterns following the periodic authorization-refresh cycle and applying the vendor-provided firmware updates immediately.

## Impact

The vulnerability carries a CVSS 3.1 base score of 9.8, indicating the potential for full system compromise. If exploited, an attacker gains root-level access to the networking device, which could be used to bypass security policies, intercept or manipulate network traffic, and maintain long-term persistence within the enterprise network infrastructure.

## Recommendation

* Apply the security patches for Junos OS Evolved provided by Juniper Networks to address CVE-2026-102031.
* Audit all devices running Junos OS Evolved to determine if the periodic TACACS+ authorization-refresh feature is enabled.
* Disable the periodic TACACS+ authorization-refresh feature on internet-facing or high-value network equipment as a temporary mitigating control until patches can be deployed.
* Monitor administrative session logs for unusual command execution patterns or unauthorized attempts to leverage the TACACS+ authorization-refresh process.
