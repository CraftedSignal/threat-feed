---
title: BPFDoor Lock File Access
slug: 2024-10-bpfdoor-lockfile-access
description: BPFDoor, an evasive Linux backdoor, is detected via the unusual access of process ID and lock files in the /var/run/ directory, indicating potential malicious activity.
date: "2026-04-01T11:18:05Z"
severities:
  - high
tags:
  - bpfdoor
  - linux
  - backdoor
  - ebpf
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1106
    technique_name: Native API
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://www.sandflysecurity.com/blog/bpfdoor-an-evasive-linux-backdoor-technical-analysis/
  - https://www.elastic.co/security-labs/a-peek-behind-the-bpfdoor
  - https://www.rapid7.com/blog/post/tr-bpfdoor-telecom-networks-sleeper-cells-threat-research-report/
  - https://github.com/rapid7/Rapid7-Labs/blob/741c7196ec12a0a56b63463d1fd726ff14d3a97a/BPFDoor/rapid7_detect_bpfdoor.sh
rules:
  - title: BPFDoor Abnormal Process ID or Lock File Accessed (proc)
    description: Detects BPFDoor .lock and .pid files access in /proc
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059
      - T1106
    data_sources:
      - file_event
      - linux
  - title: BPFDoor Abnormal Process ID or Lock File Accessed (auditd)
    description: Detects BPFDoor .lock and .pid files access based on auditd logs
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059
      - T1106
    data_sources:
      - linux
      - auditd
rules_count: 2
---

BPFDoor is an evasive Linux backdoor that utilizes extended Berkeley Packet Filter (eBPF) technology to establish stealthy communication channels and maintain persistence on compromised systems. This backdoor has been observed targeting telecom networks, acting as a sleeper cell within the infrastructure. The threat leverages eBPF for its ability to operate at a low level, making detection challenging. This threat brief focuses on detecting BPFDoor through its interaction with common PID and…
