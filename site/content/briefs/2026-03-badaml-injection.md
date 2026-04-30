---
title: BadAML Injection Allows Arbitrary Code Execution in Confidential VMs
slug: 2026-03-badaml-injection
description: The BadAML injection attack allows arbitrary code execution in confidential VMs by exploiting the ACPI interface, enabling attackers with host control to execute malicious AML code within the guest.
date: "2026-03-27T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - badaml
  - acpi
  - injection
  - confidential-computing
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://github.com/advisories/GHSA-g9ww-x58f-9g6m
  - https://blackhat.com/eu-24/briefings/schedule/#aml-injection-attacks-on-confidential-vms-42723
  - https://dl.acm.org/doi/pdf/10.1145/3719027.3765123
rules:
  - title: Detect ACPI Table Loading from Unusual Locations
    description: Detects loading of ACPI tables from unusual locations, which could indicate an attempt to inject malicious AML code.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1053
    data_sources:
      - file_event
      - linux
  - title: Detect AML Interpreter Invocation
    description: Detects invocation of the AML interpreter by monitoring for specific kernel function calls, potentially indicating malicious AML code execution.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

The BadAML injection attack, initially published in 2024, exploits the ACPI interface in confidential virtual machines, allowing for arbitrary code execution. This vulnerability arises from the ability of an attacker with control over the host to inject malicious AML (ACPI Machine Language) code. This code, embedded within ACPI tables, is passed from the host (QEMU) to the guest firmware (OVMF) and subsequently to the Linux kernel. The kernel's AML interpreter then executes this code, granting the attacker control within the guest environment. The Contrast platform versions prior to 1.18.0 are vulnerable on `Metal-QEMU-SNP` and `Metal-QEMU-SNP-GPU` platforms. Successful exploitation allows attackers to bypass security measures designed to protect confidential VMs.

## Attack Chain

1.  Attacker gains control over the host machine running the QEMU hypervisor.
2.  Attacker crafts a malicious ACPI table containing arbitrary AML code.
3.  The malicious ACPI table is injected into the guest VM via QEMU.
4.  The OVMF firmware in the guest VM parses the ACPI table and passes the AML code to the Linux kernel.
5.  The Linux kernel's AML interpreter executes the injected AML code.
6.  The AML code leverages its access to guest memory to escalate privileges.
7.  The attacker gains arbitrary code execution within the guest VM.
8.  The attacker can then perform malicious actions, such as data exfiltration or further compromise of the system.

## Impact

Successful exploitation of the BadAML vulnerability allows attackers to execute arbitrary code within confidential VMs, potentially leading to data theft, service disruption, or complete system compromise. While the number of victims is unknown, the affected sectors include any environment utilizing the vulnerable Contrast platforms (`Metal-QEMU-SNP` and `Metal-QEMU-SNP-GPU`) for confidential computing. The impact is significant, as it undermines the security guarantees provided by confidential computing technologies.

## Recommendation

*   Upgrade Contrast installations on `Metal-QEMU-SNP` and `Metal-QEMU-SNP-GPU` platforms to version 1.18.0 or later to incorporate the kernel patch.
*   Monitor host systems for suspicious ACPI table modifications using custom scripts or host-based intrusion detection systems (no specific rule provided, but ACPI table modification events should be logged where possible).
