---
title: CIFSwitch Linux Kernel Local Privilege Escalation Vulnerability
slug: 2026-05-cifswitch-lpe
description: The CIFSwitch vulnerability in the Linux kernel allows an unprivileged user to forge CIFS authentication key descriptions, abuse the kernel's key request mechanism, and gain root privileges by loading a malicious NSS module.
date: "2026-05-30T14:23:52Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - privilege-escalation
  - linux
  - cifs
  - kernel
vendors:
  - Canonical
  - Red Hat
  - Oracle
  - Amazon
  - SUSE
products:
  - Linux Mint
  - CentOS Stream
  - Rocky Linux
  - AlmaLinux
  - Kali Linux
  - SLES
  - Ubuntu
  - Debian
  - Pop!_OS
  - openSUSE
  - Oracle Linux
  - Amazon Linux
  - cifs-utils
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://www.bleepingcomputer.com/news/security/new-cifswitch-linux-flaw-gives-root-on-multiple-distributions/
rules:
  - title: Detect Suspicious cifs.upcall Execution
    description: Detects suspicious executions of cifs.upcall potentially indicating CIFSwitch exploitation. This rule identifies when cifs.upcall is executed with a parent process that is not a standard system process.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
  - title: Detect Potential CIFSwitch - Namespace Switch
    description: Detects potential exploitation of CIFSwitch by monitoring for commands that switch namespaces (nsenter, unshare) potentially used to prepare the environment for the exploit.
    platform: sigma
    severity: low
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A newly discovered local privilege escalation vulnerability named 'CIFSwitch' affects the Linux kernel. This vulnerability, introduced in 2007, allows an unprivileged user to forge CIFS authentication key descriptions and abuse the kernel's key request mechanism to gain root privileges. The issue stems from the kernel's CIFS subsystem failing to properly validate the origin of `cifs.spnego` key requests. Successful exploitation depends on factors like a vulnerable kernel version, a vulnerable `cifs-utils` version (6.14 and higher, with some older variants also affected), the availability of user namespaces, and permissive SELinux/AppArmor policies. Several distributions, including Linux Mint 21.3/22.3, CentOS Stream 9, Rocky Linux 9, AlmaLinux 9, Kali Linux 2021.4-2026.1, and SLES 15 SP7, are confirmed to be vulnerable with their default configurations. Exploitation can lead to complete system compromise.

## Attack Chain

1. An unprivileged user crafts a forged `cifs.spnego` key request.
2. The forged request is sent to the Linux keyring subsystem.
3. The kernel, lacking proper validation, triggers the normal authentication workflow.
4. The root-privileged `cifs.upcall` helper is invoked.
5. The `cifs.upcall` helper trusts attacker-controlled fields, assuming they originated from the kernel.
6. The attacker abuses these fields to force a namespace switch.
7. The attacker triggers a Name Service Switch (NSS) lookup.
8. Before privileges are dropped, a malicious NSS module is loaded, resulting in root code execution.

## Impact

Successful exploitation of CIFSwitch results in a local attacker gaining root privileges on the affected Linux system. This allows the attacker to execute arbitrary code with the highest level of privilege, potentially leading to data theft, system corruption, or complete system takeover. The vulnerability impacts several popular Linux distributions and could affect numerous systems if not patched or mitigated. While the researcher has confirmed vulnerability in some distributions, successful exploitation depends on specific configuration factors.

## Recommendation

*   Apply the kernel patch that adds validation of `cifs.spnego` request origins (upstream commit 3da1fdf) to remediate the vulnerability.
*   If the CIFS module is not used, disable or blacklist it to prevent potential exploitation.
*   Remove the `cifs-utils` package if it is not necessary for system functionality.
*   Disable unprivileged user namespaces to limit the attack surface.
*   Monitor for unexpected `cifs.upcall` executions, especially those initiated by unprivileged users, using a process creation rule.
*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment.
