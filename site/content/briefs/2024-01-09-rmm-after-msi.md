---
title: Remote Management Access Launch After MSI Install
slug: 2024-01-09-rmm-after-msi
description: Detects a suspicious sequence of an MSI installer execution immediately followed by the execution of commonly abused Remote Management Software, potentially indicating unauthorized remote access.
date: "2024-01-09T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - remote-access
  - command-and-control
  - rmm
  - msi
vendors:
  - ConnectWise
  - SyncroMSP
  - TightVNC
  - UltraVNC
products:
  - ScreenConnect
  - Syncro
  - TightVNC
  - UltraVNC
references:
  - https://attack.mitre.org/techniques/T1219/
rules:
  - title: MSI Install Followed by Remote Management Tool Execution
    description: Detects MSI installer execution followed by the execution of commonly abused Remote Management Software.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1219
    data_sources:
      - process_creation
      - windows
  - title: Suspicious ScreenConnect Guest Access
    description: Detects connections to ScreenConnect servers with guest access parameters, potentially indicating unauthorized access.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1219
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This detection identifies a specific sequence of events on Windows systems: the execution of an MSI installer followed shortly by the launch of remote management software (RMM). Attackers might leverage this technique to gain unauthorized remote access to systems. The initial MSI installation could be triggered via social engineering or other means. The subsequent RMM connection might be established using guest links with known session keys. The rule focuses on detecting commonly abused RMM tools like ScreenConnect, Syncro, and others. The timeframe of interest is within one minute of the MSI execution. This matters to defenders because it can indicate malicious actors attempting to establish persistent remote access for command and control or data exfiltration.

## Attack Chain

1. An attacker gains initial access to a target system (e.g., through social engineering or exploiting a vulnerability).
2. The attacker delivers a malicious or compromised MSI installer to the target system.
3. The user executes the MSI installer (`msiexec.exe /i <malicious_package.msi>`).
4. The attacker uses the MSI installation as a pretext or smokescreen for their real objective.
5. Immediately after the MSI installation, the attacker initiates a Remote Management Software (RMM) client. This can be done by directly executing ScreenConnect.ClientService.exe with parameters specifying an Access connection as a Guest user, or a similar method with Syncro or other RMM tools like tvnserver.exe or winvnc.exe.
6. The RMM client connects to the attacker-controlled server, granting the attacker remote access.
7. The attacker leverages the established remote connection to perform malicious activities, such as data exfiltration, lateral movement, or further exploitation.

## Impact

Successful exploitation can lead to unauthorized remote access to the compromised system. The impact includes potential data theft, installation of malware, lateral movement within the network, and disruption of services. While the source doesn't specify a victim count, widespread use of vulnerable RMM software could lead to a broad compromise across various sectors.

## Recommendation

*   Deploy the Sigma rule "MSI Install Followed by Remote Management Tool Execution" to detect suspicious sequences of MSI installations and RMM tool launches (see 'rules' section).
*   Deploy the Sigma rule "Suspicious ScreenConnect Guest Access" to detect connections to ScreenConnect servers with guest access parameters (see 'rules' section).
*   Monitor process execution events for `msiexec.exe` and known RMM tools such as `ScreenConnect.ClientService.exe`, `Syncro.Installer.exe`, `tvnserver.exe`, and `winvnc.exe` (see 'rules' section and enable relevant logging).
*   Investigate any instances of MSI installations followed by RMM software execution, especially if the RMM software is not authorized or commonly used within the organization.
