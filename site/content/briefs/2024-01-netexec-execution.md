---
title: Detection of NetExec Hacktool Execution
slug: 2024-01-netexec-execution
description: The threat brief details the detection of NetExec (formerly CrackMapExec), a post-exploitation tool used for Active Directory penetration testing and network enumeration, often employed by threat actors for lateral movement and credential harvesting.
date: "2024-01-03T14:35:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - pentest
  - post-exploitation
  - lateral-movement
  - active-directory
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1018
    technique_name: Remote System Discovery
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
references:
  - https://thedfirreport.com/2025/12/17/cats-got-your-files-lynx-ransomware/
  - https://github.com/Pennyw0rth/NetExec
  - https://www.netexec.wiki/
rules:
  - title: HackTool - NetExec Execution
    description: Detects execution of the hacktool NetExec based on process name and command-line arguments.
    platform: sigma
    severity: high
    tactics:
      - discovery
      - lateral-movement
    techniques:
      - T1018
      - T1021
    data_sources:
      - process_creation
      - windows
  - title: NetExec Execution with Specific Protocol
    description: Detects NetExec execution focusing on specific protocols used for lateral movement.
    platform: sigma
    severity: medium
    tactics:
      - lateral-movement
    techniques:
      - T1021
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

NetExec, previously known as CrackMapExec, is a post-exploitation tool commonly used during Active Directory penetration testing. It is also favored by red teams and malicious actors for reconnaissance, lateral movement, and credential harvesting within Windows networks. This tool allows for the enumeration of hosts, exploitation of network services, and remote command execution. The use of NetExec in an enterprise environment is considered suspicious due to its capabilities for identifying vulnerable systems and facilitating unauthorized access. Defenders should monitor for its execution, as it is often a precursor to more serious attacks, including ransomware deployment, such as the Lynx ransomware.

## Attack Chain

1.  An attacker gains initial access to a Windows system via an exploit or compromised credentials.
2.  NetExec (nxc.exe) is deployed on the compromised host, often copied to a temporary directory.
3.  NetExec is executed with commands to enumerate network shares and identify potential targets using SMB.
4.  The tool uses LDAP to query Active Directory for user accounts, groups, and organizational units.
5.  NetExec attempts to authenticate to other systems using gathered or compromised credentials via protocols such as SMB, SSH, or RDP.
6.  Successful authentication allows for remote command execution via WMI or WinRM.
7.  The attacker leverages identified vulnerabilities or misconfigurations to escalate privileges on the target systems.
8.  The attacker moves laterally through the network, gaining access to sensitive data or deploying ransomware like Lynx.

## Impact

Successful execution of NetExec can lead to widespread compromise within an Active Directory environment. Attackers can identify and exploit vulnerable systems, harvest credentials, and move laterally to gain access to critical assets. This can result in data theft, system disruption, and ransomware deployment, potentially affecting hundreds or thousands of systems depending on the size of the organization. The tool is often used as a precursor to ransomware attacks, where entire networks can be encrypted, leading to significant financial and reputational damage.

## Recommendation

*   Deploy the Sigma rule `HackTool - NetExec Execution` to your SIEM to detect the execution of NetExec based on process creation logs.
*   Monitor process creation events for `nxc.exe` with command-line arguments associated with network protocols like `ftp`, `ldap`, `mssql`, `nfs`, `rdp`, `smb`, `ssh`, `vnc`, `winrm`, and `wmi`.
*   Implement strict access controls and regularly audit Active Directory to minimize the potential for lateral movement.
*   Consider using application control solutions to prevent the execution of unauthorized tools like `nxc.exe`.
