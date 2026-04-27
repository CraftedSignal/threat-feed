---
title: BadAML Injection Allows Arbitrary Code Execution in Confidential VMs
slug: 2026-03-badaml-injection
description: The BadAML injection attack allows arbitrary code execution in confidential VMs by exploiting the ACPI interface, enabling attackers with host control to execute malicious AML code within the guest.
date: "2026-03-27T12:00:00Z"
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

The BadAML injection attack, initially published in 2024, exploits the ACPI interface in confidential virtual machines, allowing for arbitrary code execution. This vulnerability arises from the ability of an attacker with control over the host to inject malicious AML (ACPI Machine Language) code. This code, embedded within ACPI tables, is passed from the host (QEMU) to the guest firmware (OVMF) and subsequently to the Linux kernel. The kernel's AML interpreter then executes this code, granting…
