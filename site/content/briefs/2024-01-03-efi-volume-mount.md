---
title: Windows EFI Volume Mount Attempt via Mountvol
slug: 2024-01-03-efi-volume-mount
description: Detection of attempts to mount the EFI volume on a Windows system, potentially indicating malicious activity aimed at modifying the system's boot process.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - efi
  - mountvol
  - privilege-escalation
  - persistence
  - bootkit
vendors:
  - Splunk
products:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1542
    technique_name: Pre-OS Boot
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562.009
    technique_name: 'Impair System Defenses: Safe Boot Mode'
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1204.002
    technique_name: 'User Execution: Malicious File'
references:
  - https://www.binarly.io/blog/pkfail-untrusted-platform-keys-undermine-secure-boot-on-uefi-ecosystem
rules:
  - title: Detect EFI Volume Mount via Mountvol
    description: Detects attempts to mount the EFI volume using mountvol.exe with specific command-line arguments.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1542
    data_sources:
      - process_creation
      - windows
  - title: Detect EFI Volume Mount via Mountvol - Alternate File Name
    description: Detects attempts to mount the EFI volume using MOUNTVOL.EXE with specific command-line arguments. This rule detects the alternate file name.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1542
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The EFI system partition (ESP) is a critical component of modern Windows systems, containing bootloaders, device drivers, and system utilities necessary for the system to boot. Attackers may attempt to mount this volume to modify its contents, potentially compromising the boot process and gaining persistent control over the system. The `mountvol.exe` utility is a legitimate Windows tool that can be used to manage volume mount points, but its use to mount the EFI volume is uncommon and can be indicative of malicious activity. This activity is often seen with attacks such as PKFail. Defenders should monitor for the execution of `mountvol.exe` with command-line arguments that target the EFI system partition.

## Attack Chain

1.  An attacker gains initial access to a Windows system, potentially through social engineering or exploiting a software vulnerability.
2.  The attacker escalates privileges to administrator or system level to allow the mounting of volumes.
3.  The attacker executes `mountvol.exe` with the `/s` switch or other parameters to mount the EFI system partition (ESP).
4.  The attacker modifies the contents of the ESP, such as replacing bootloaders or injecting malicious drivers.
5.  The attacker unmounts the volume to avoid detection.
6.  The system is rebooted, and the attacker's malicious code is executed during the boot process.
7.  The attacker gains persistent control over the system.
8.  The attacker performs lateral movement or data exfiltration.

## Impact

Successful mounting of the EFI volume can allow attackers to compromise the boot process, install rootkits, or disable security features. This can lead to persistent malware infections that are difficult to detect and remove. The modifications to the boot process can allow attackers to bypass security controls and gain complete control over the compromised system, leading to data theft, system disruption, or further attacks on the network.

## Recommendation

*   Deploy the Sigma rule `Detect EFI Volume Mount via Mountvol` to your SIEM and tune for your environment.
*   Monitor process creation events for instances of `mountvol.exe` executing with the `-S` flag using Sysmon Event ID 1, as covered by the provided Sigma rule.
*   Review parent processes of `mountvol.exe` executions for suspicious or unauthorized activity.
*   Implement application control policies to restrict the execution of `mountvol.exe` to authorized users and processes.
*   Investigate systems where `mountvol.exe` has been used to mount the EFI volume for signs of compromise.
*   Monitor Windows Event Log Security 4688 for process creation events related to `mountvol.exe`.
