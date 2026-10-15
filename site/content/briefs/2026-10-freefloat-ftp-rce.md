---
title: Stack Buffer Overflow in FreeFloat FTP Server
slug: 2026-10-freefloat-ftp-rce
description: A stack-based buffer overflow in FreeFloat FTP Server 1.0 allows remote, unauthenticated attackers to achieve arbitrary code execution via crafted FTP commands.
date: "2026-10-15T20:04:21Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:freefloat:ftp_server:1.0:*:*:*:*:*:*:*
  - cpe:2.3:a:freefloat:freefloat_ftp_server:1.0:*:*:*:*:*:*:*
tags:
  - buffer-overflow
  - rce
  - ftp
vendors:
  - FreeFloat
products:
  - FreeFloat FTP Server (1.0)
affected_os:
  - Windows XP
  - Windows 7
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1210
    technique_name: Exploitation of Remote Services
    evidence: The vulnerability allows for a stack-based buffer overflow in FreeFloat FTP Server allowing code execution via crafted input.
    confidence_band: high
cves:
  - id: CVE-2025-5548
    cvss: 7.3
    epss: 0.14985
references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-JAVYAN05-CVE-2025-5548
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Inventory all servers running FreeFloat FTP Server.
      owner: IT Operations
      due: 24h
      evidence: Source identifies FreeFloat FTP Server 1.0 as the vulnerable product.
  mitigation_plan:
    - priority: immediate
      action: Decommission all instances of FreeFloat FTP Server 1.0.
      owner: IT Operations
      addresses: CVE-2025-5548
      evidence: Software is legacy and lacks security patches for this RCE vulnerability.
---

CVE-2025-5548 describes a critical stack-based buffer overflow vulnerability in FreeFloat FTP Server version 1.0. The vulnerability allows an unauthenticated, remote attacker to execute arbitrary code by sending malformed or excessively long strings to the FTP service. The issue stems from insecure handling of client input within the server process, leading to EIP register overwrite and control over the execution flow. 

As of October 2026, proof-of-concept (PoC) exploit code has been publicly released, detailing the methodology for triggering a controlled crash, identifying the EIP offset, and executing shellcode via JMP ESP gadgets. Given the nature of the service, which often runs with high privileges on older Windows operating systems (Windows 7/XP), successful exploitation grants an attacker full system access. Defenders should prioritize auditing internal environments for legacy FreeFloat FTP instances, which are now high-risk due to the availability of reliable, weaponized PoC material.

## Attack Chain

1. The attacker performs service discovery to locate internet-facing or internal FreeFloat FTP Server instances.
2. The attacker uses a fuzzer or crafted scripts to send oversized input strings to the FTP service.
3. The service fails to validate the input length, causing an overflow of the stack buffer.
4. The input overwrites the EIP register, allowing the attacker to redirect the instruction pointer.
5. The attacker identifies the EIP offset and specific bad characters that must be avoided in the payload.
6. The attacker locates a JMP ESP instruction gadget within the application or its loaded modules to redirect execution to the shellcode.
7. The attacker deploys a payload (e.g., reverse shellcode generated via msfvenom) within the overflowed buffer.
8. The service executes the injected shellcode, providing the attacker with a remote command shell on the victim machine.

## Impact

Successful exploitation leads to full compromise of the host system, enabling remote arbitrary code execution with the privileges of the FTP service. This poses a severe risk to organizations still utilizing legacy FTP services for file transfer, as the exploit is reliable and requires no authentication. The vulnerability is applicable to legacy environments, particularly those running Windows XP or Windows 7, where memory protection mechanisms may be less robust than modern operating systems.

## Recommendation

Prioritize the immediate decommissioning of FreeFloat FTP Server from the environment, as the software is legacy and vulnerable to exploitation. 
If immediate decommissioning is not feasible, restrict network access to the FTP service to known, trusted IP addresses using host-based firewalls or network segmentation. 
Monitor process creation events for unusual child processes (e.g., cmd.exe, powershell.exe) spawned by the FTP server process.
