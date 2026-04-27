---
title: QEMU Hypervisor Escape via virtio-snd 0-Day
slug: 2026-03-qemu-escape
description: An unpatched vulnerability in QEMU's virtio-snd component allows for a hypervisor escape due to an uncontrolled heap overflow.
date: "2026-03-19T05:19:00Z"
severities:
  - critical
tags:
  - virtualization
  - hypervisor
  - qemu
  - virtio-snd
  - heap overflow
  - hypervisor escape
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
references:
  - https://www.reddit.com/r/netsec/comments/1rxrq07/from_virtiosnd_0day_to_hypervisor_escape/
  - https://osec.io/blog/2026-03-17-virtio-snd-qemu-hypervisor-escape/
rules:
  - title: Detect QEMU Process Spawning Shell
    description: Detects QEMU processes spawning shell processes, which may indicate a hypervisor escape attempt.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
  - title: Detect QEMU Outbound Network Connection
    description: Detects QEMU processes making outbound network connections, which may indicate a hypervisor escape attempt leading to C2.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

A recently disclosed vulnerability in the QEMU virtualization platform allows a malicious guest operating system to escape the hypervisor and potentially execute code on the host system. The vulnerability resides in the `virtio-snd` component, which emulates a sound card for virtual machines. The root cause is an uncontrolled heap overflow that can be triggered by a specially crafted audio stream sent from the guest to the host. While specific details of the vulnerability and its exploitation…
