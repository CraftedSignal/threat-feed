---
title: BPFDoor Lock File Access
slug: 2024-10-bpfdoor-lockfile-access
description: BPFDoor, an evasive Linux backdoor, is detected via the unusual access of process ID and lock files in the /var/run/ directory, indicating potential malicious activity.
date: "2026-04-01T11:18:05Z"
type: coverage
types:
  - coverage
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

BPFDoor is an evasive Linux backdoor that utilizes extended Berkeley Packet Filter (eBPF) technology to establish stealthy communication channels and maintain persistence on compromised systems. This backdoor has been observed targeting telecom networks, acting as a sleeper cell within the infrastructure. The threat leverages eBPF for its ability to operate at a low level, making detection challenging. This threat brief focuses on detecting BPFDoor through its interaction with common PID and lock files in the `/var/run` directory, where it attempts to masquerade as legitimate processes or services. The access of these files by unauthorized or unexpected processes can be a strong indicator of BPFDoor activity.

## Attack Chain

1.  The attacker gains initial access to the Linux system, possibly through exploitation of a vulnerability or stolen credentials (not detailed in source).
2.  The attacker deploys the BPFDoor backdoor onto the compromised system.
3.  BPFDoor establishes persistence by injecting itself into the kernel using eBPF.
4.  BPFDoor attempts to blend in with legitimate system activity by accessing or manipulating process ID (.pid) and lock (.lock) files in the `/var/run` directory.
5.  Specifically, BPFDoor may access files like `/var/run/aepmonend.pid`, `/var/run/auditd.lock`, `/var/run/cma.lock`, `/var/run/console-kit.pid`, `/var/run/consolekit.pid`, `/var/run/daemon.pid`, `/var/run/hald-addon.pid`, `/var/run/hald-smartd.pid`, `/var/run/haldrund.pid`, `/var/run/hp-health.pid`, `/var/run/hpasmlit.lock`, `/var/run/hpasmlited.pid`, `/var/run/kdevrund.pid`, `/var/run/lldpad.lock`, `/var/run/mcelog.pid`, `/var/run/system.pid`, `/var/run/uvp-srv.pid`, `/var/run/vmtoolagt.pid`, and `/var/run/xinetd.lock`.
6.  This access may involve reading, writing, or modifying these files to conceal its presence.
7.  BPFDoor uses the eBPF-based communication channel to receive commands from a remote attacker.
8.  The attacker executes arbitrary commands on the compromised system, potentially leading to data theft, system disruption, or further lateral movement.

## Impact

A successful BPFDoor infection can lead to a persistent and stealthy backdoor on a Linux system. Given the nature of eBPF, detection is difficult, potentially allowing attackers long-term access to the system and sensitive data. Telecom networks are specifically mentioned, indicating potential disruption of critical communications infrastructure. The number of victims and specific damage caused varies per deployment.

## Recommendation

*   Deploy the Sigma rule `BPFDoor Abnormal Process ID or Lock File Accessed` to your SIEM to detect suspicious access to lock and PID files in `/var/run` based on auditd logs.
*   Investigate any alerts triggered by the Sigma rule, focusing on identifying the process accessing the lock or PID file and whether it is legitimate.
*   Implement network monitoring to identify unusual eBPF activity.
*   Regularly review and update intrusion detection systems (IDS) signatures to include known BPFDoor indicators.
