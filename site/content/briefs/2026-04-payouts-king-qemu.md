---
title: Payouts King Ransomware Abusing QEMU VMs for Defense Evasion
slug: 2026-04-payouts-king-qemu
description: The Payouts King ransomware is leveraging QEMU VMs as a reverse SSH backdoor to execute payloads, store malicious files, and establish covert remote access tunnels, bypassing endpoint security measures.
date: "2026-04-18T12:00:00Z"
type: threat
types:
  - threat
severities:
  - critical
actors:
  - GOLD ENCOUNTER
tags:
  - payouts-king
  - ransomware
  - qemu
  - vm
  - defense-evasion
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053.005
    technique_name: 'Scheduled Task/Job: Scheduled Task'
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1622
    technique_name: Masquerade Task or Service
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003.001
    technique_name: 'OS Credential Dumping: LSASS Memory'
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1574.002
    technique_name: 'Hijack Execution Flow: DLL Side-Loading'
cves:
  - id: CVE-2025-26399
    cvss: 9.8
    epss: 0.26563
references:
  - https://www.bleepingcomputer.com/news/security/payouts-king-ransomware-uses-qemu-vms-to-bypass-endpoint-security/
iocs:
  - type: cve
    value: CVE-2025-26399
ioc_counts:
  cve: 1
rules:
  - title: Detect QEMU Process Creation
    description: Detects the execution of QEMU processes, which may indicate malicious use of virtualization for defense evasion.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1622
    data_sources:
      - process_creation
      - windows
  - title: Detect ADNotificationManager Sideloading Havoc C2
    description: Detects the use of ADNotificationManager.exe to sideload the Havoc C2 payload (vcruntime140_1.dll).
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1574.002
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The Payouts King ransomware, associated with the GOLD ENCOUNTER threat group, is utilizing QEMU, an open-source CPU emulator, to run hidden Alpine Linux virtual machines (VMs) on compromised Windows systems, effectively bypassing endpoint security solutions. This technique allows attackers to execute malicious payloads, store sensitive data, and create covert remote access tunnels over SSH without being detected by host-based security tools. Observed since November 2025 (tracked as STAC4713), this campaign initially exploited exposed SonicWall VPNs and the SolarWinds Web Help Desk vulnerability (CVE-2025-26399). More recent attacks have leveraged exposed Cisco SSL VPNs and Microsoft Teams phishing campaigns to deliver payloads. The attackers are likely tied to former BlackBasta affiliates based on similar initial access methods. This tactic enables persistence, elevated privileges, and data exfiltration while evading detection.

## Attack Chain

1.  **Initial Access:** Attackers gain initial access through exposed SonicWall VPNs, Cisco SSL VPNs, or by exploiting the SolarWinds Web Help Desk vulnerability (CVE-2025-26399). Alternatively, they use Microsoft Teams phishing, tricking employees into downloading and executing malicious files via QuickAssist.
2.  **Payload Delivery:** In some instances, a legitimate ADNotificationManager.exe binary is used to sideload a Havoc C2 payload (vcruntime140_1.dll).
3.  **QEMU Deployment:** A scheduled task named ‘TPMProfiler’ is created to launch a hidden QEMU VM as SYSTEM, utilizing virtual disk files disguised as databases and DLL files.
4.  **VM Configuration:** The QEMU VM runs Alpine Linux (version 3.22.0), containing attacker tools such as AdaptixC2, Chisel, BusyBox, and Rclone.
5.  **Reverse SSH Tunnel:** Port forwarding is set up to establish a reverse SSH tunnel, providing covert access to the infected host.
6.  **Credential Access:** Attackers use VSS (vssuirun.exe) to create a shadow copy, then use the print command over SMB to copy NTDS.dit, SAM, and SYSTEM hives to temp directories.
7.  **Data Exfiltration:** Rclone is leveraged to exfiltrate data to a remote SFTP location or other exfiltration methods, such as FTP, are used.
8.  **Encryption and Extortion:** The Payouts King ransomware encrypts systems using AES-256 (CTR) with RSA-4096 with intermittent encryption for larger files. Ransom notes are dropped, directing victims to leak sites on the dark web.

## Impact

Successful Payouts King ransomware attacks can result in significant data loss, system downtime, and financial repercussions for victim organizations. The use of QEMU VMs provides an additional layer of stealth, making detection and remediation more challenging. Targeted sectors are not specified in this report, but the use of exposed VPNs and phishing suggests a broad targeting scope. The ransom demands and potential data leaks on the dark web further compound the damage.

## Recommendation

*   Monitor for unauthorized QEMU installations and suspicious scheduled tasks running with SYSTEM privileges, as these are key indicators of compromise (see Overview).
*   Implement network monitoring to detect unusual SSH port forwarding and outbound SSH tunnels on non-standard ports, which could indicate a reverse SSH tunnel (see Attack Chain).
*   Deploy the Sigma rule "Detect ADNotificationManager Sideloading Havoc C2" to identify instances where ADNotificationManager.exe is used to sideload the Havoc C2 payload (vcruntime140_1.dll) (see Rules).
*   Review and patch CVE-2025-26399 in SolarWinds Web Help Desk and apply necessary security measures for exposed SonicWall and Cisco SSL VPNs to prevent initial access (see Attack Chain).
*   Monitor for processes creating shadow copies (vssuirun.exe) followed by unusual file access patterns (NTDS.dit, SAM, SYSTEM hives) via SMB, indicative of credential theft (see Attack Chain).
