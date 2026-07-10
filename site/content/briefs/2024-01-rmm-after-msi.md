---
title: Remote Management Software Launch After MSI Install
slug: 2024-01-rmm-after-msi
description: Attackers are leveraging MSI installers to deploy remote management software (RMM) such as ScreenConnect, Syncro, and VNC, potentially indicating unauthorized access and control over compromised systems.
date: "2024-01-30T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - remote-access
  - rmm
  - msi
  - command-and-control
vendors:
  - ConnectWise
  - Syncro
  - TightVNC
  - RealVNC
products:
  - ConnectWise ScreenConnect
  - Syncro RMM
  - TightVNC
  - RealVNC
references:
  - https://attack.mitre.org/techniques/T1219/
rules:
  - title: Remote Management Access Launch After MSI Install
    description: Detects an MSI installer execution followed by the execution of commonly abused Remote Management Software like ScreenConnect.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1219
    data_sources:
      - process_creation
      - windows
  - title: Syncro RMM Install with Config and Key
    description: Detects execution of Syncro installer with suspicious arguments.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1219
    data_sources:
      - process_creation
      - windows
  - title: VNC Server Execution
    description: Detects execution of VNC server applications.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1219
    data_sources:
      - process_creation
      - windows
rules_count: 3
---

This threat involves the abuse of MSI installers to deploy and launch remote management software (RMM) on Windows systems. The observed behavior consists of an MSI installer executing, followed by the execution of commonly abused RMM tools like ScreenConnect, Syncro, or VNC. This activity often signifies unauthorized access, where attackers trigger an MSI installation and then connect via a guest link or preconfigured session key. This technique allows attackers to gain persistent remote access to compromised systems. The activity is typically observed within a short timeframe (1 minute) between the MSI installation and the RMM launch. This allows threat actors to bypass traditional access controls and establish a foothold for further malicious activities.

## Attack Chain

1.  User executes a seemingly legitimate MSI installer package (e.g., downloaded from a malicious link or delivered via social engineering).
2.  `msiexec.exe` process starts with the `/i` argument, initiating the installation process. Parent process is typically `explorer.exe` or `sihost.exe`.
3.  The MSI installer may drop additional files or modify registry settings as part of its installation routine.
4.  Within one minute of the MSI installation, a remote management software client (e.g., `ScreenConnect.ClientService.exe`, `Syncro.Installer.exe`, `tvnserver.exe`, or `winvnc.exe`) is executed.
5.  The RMM software connects to a remote server controlled by the attacker. ScreenConnect connection strings are commonly observed with parameters such as `?e=Access&y=Guest&h*&k=*`.
6.  The attacker uses the RMM software to gain remote access to the compromised system.
7.  The attacker performs reconnaissance, privilege escalation, or lateral movement within the network.
8.  The attacker deploys additional malware, exfiltrates sensitive data, or performs other malicious activities based on their objectives.

## Impact

Successful exploitation can lead to unauthorized remote access, data theft, malware deployment, and system compromise. This technique can impact organizations across various sectors, especially those relying on remote access solutions. The ability to remotely control compromised systems can enable attackers to perform a wide range of malicious activities, including data exfiltration, ransomware deployment, and intellectual property theft.

## Recommendation

*   Deploy the Sigma rule "Remote Management Access Launch After MSI Install" to your SIEM and tune it for your environment to detect suspicious RMM launches after MSI installations.
*   Investigate any instances of `msiexec.exe` executing with the `/i` parameter followed by the launch of RMM tools, as detected by the Sigma rule.
*   Monitor process creation events for `ScreenConnect.ClientService.exe`, `Syncro.Installer.exe`, `tvnserver.exe`, and `winvnc.exe` using process creation logs.
*   Review network connection logs for connections initiated by the aforementioned RMM tools to external IPs.
*   Implement application control policies to restrict the execution of unauthorized RMM tools.
