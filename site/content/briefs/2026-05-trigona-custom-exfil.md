---
title: Trigona Ransomware Employing Custom Data Exfiltration Tool
slug: 2026-05-trigona-custom-exfil
description: Trigona ransomware is using a custom data exfiltration tool named 'uploader_client.exe' to steal data from compromised environments, enhancing speed and evasion.
date: "2026-04-23T19:02:17Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - Trigona
tags:
  - trigona
  - ransomware
  - data exfiltration
  - custom tool
vendors:
  - Microsoft
  - Nirsoft
  - AnyDesk
products:
  - Windows
  - AnyDesk
  - Mimikatz
  - PowerRun
mitre_ttps:
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1071
    technique_name: Application Layer Protocol
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1027
    technique_name: Obfuscated Files or Information
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1021
    technique_name: Remote Services
references:
  - https://www.bleepingcomputer.com/news/security/trigona-ransomware-attacks-use-custom-exfiltration-tool-to-steal-data/
iocs:
  - type: file
    value: uploader_client.exe
ioc_counts:
  file: 1
rules:
  - title: Detect Trigona Custom Exfiltration Tool Execution
    description: Detects execution of the Trigona custom data exfiltration tool 'uploader_client.exe'.
    platform: sigma
    severity: high
    tactics:
      - exfiltration
    techniques:
      - T1071.001
    data_sources:
      - process_creation
      - windows
  - title: Detect PowerRun Execution Followed by Credential Dumping
    description: Detects PowerRun execution followed by Mimikatz execution, indicating potential privilege escalation and credential theft.
    platform: sigma
    severity: critical
    tactics:
      - credential_access
      - privilege_escalation
    techniques:
      - T1003
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Trigona ransomware, initially launched in October 2022, has been observed using a custom command-line tool named "uploader_client.exe" to exfiltrate data from compromised environments. This shift, observed in March 2026, suggests an effort to avoid detection by security solutions that commonly flag publicly available tools like Rclone and MegaSync. Symantec researchers believe this indicates a strategic investment in proprietary malware to maintain a lower profile during critical phases of attacks. The custom tool supports five simultaneous connections per file for faster data exfiltration via parallel uploads, rotates TCP connections after 2GB of traffic to evade monitoring, offers options for selective file type exfiltration, and utilizes an authentication key to restrict access to stolen data. Despite disruptions in October 2023, Trigona has resumed operations, incorporating additional techniques like installing the Huorong Network Security Suite tool HRSword and disabling security products.

## Attack Chain

1. Initial compromise of the target system through unspecified means.
2. Installation of the Huorong Network Security Suite tool HRSword as a kernel driver service.
3. Deployment of tools such as PCHunter, Gmer, YDark, WKTools, DumpGuard, and StpProcessMonitorByovd to disable security-related products by leveraging vulnerable kernel drivers to terminate endpoint protection processes.
4. Execution of utilities with PowerRun to launch apps, executables, and scripts with elevated privileges, bypassing user-mode protections.
5. Deployment of AnyDesk for direct remote access to the breached systems.
6. Execution of Mimikatz and Nirsoft utilities for credential theft and password recovery operations.
7. Use of the custom "uploader_client.exe" to exfiltrate valuable documents such as invoices and PDFs from network drives via parallel uploads, rotating TCP connections to evade monitoring, and using an authentication key to restrict data access.
8. Final stage involving the deployment of Trigona ransomware, demanding ransom payment in Monero cryptocurrency.

## Impact

Successful Trigona ransomware attacks result in significant data theft and encryption, disrupting business operations and causing financial losses. The group has demonstrated the capability to resume operations even after suffering disruptions, indicating a persistent threat. Observed data exfiltration has included high-value documents such as invoices and PDFs, demonstrating a targeted approach to data theft. Victims face potential regulatory penalties, reputational damage, and recovery costs associated with restoring systems and data. The number of victims and specific financial impact varies per campaign, but the potential for severe disruption and financial strain is consistent.

## Recommendation

*   Monitor process creation events for the execution of "uploader_client.exe" with command-line arguments indicative of data exfiltration (see Sigma rule below).
*   Implement network monitoring to detect connections to unusual or hardcoded server addresses used by the "uploader_client.exe" exfiltration tool (see IOC table).
*   Deploy endpoint detection rules to identify the installation of Huorong Network Security Suite (HRSword) as a kernel driver service and tools like PCHunter, Gmer, YDark, WKTools, DumpGuard, and StpProcessMonitorByovd.
*   Monitor for processes launched via PowerRun, especially if followed by credential dumping or remote access tool execution.
*   Review AnyDesk usage for unusual connections or after-hours access, as this tool is used for remote access.
*   Enable robust logging for credential access attempts and password recovery activity associated with Mimikatz and Nirsoft tools.
