---
title: Fake LastPass Authenticator Installer Deploys BYOVD Security-Disabling Kernel Driver
slug: 2026-09-fake-lastpass-installer
description: Threat actors are distributing a credential-stealing payload via fake GitHub repositories that uses a legitimate Microsoft-signed driver to disable security software via kernel-level process termination.
date: "2026-09-21T18:26:11Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - credential-theft
  - malware
  - byovd
  - windows
  - persistence
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1543.003
    technique_name: Windows Service
    evidence: The loader then tries three ways to gain administrator rights, reaches SYSTEM, the highest level on a Windows machine, and installs the kernel driver as a service.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562.001
    technique_name: 'Impair Defenses: Disable or Modify Tools'
    evidence: This one, which the researchers named Alinubx.sys, carries a list of 145 antivirus and security process names and terminates each one it finds running.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1574.002
    technique_name: DLL Side-Loading
    evidence: When the fake installer runs, Windows loads the attacker's DLL from the same folder, a trick called DLL side-loading.
    confidence_band: high
rules:
  - title: Detect Suspicious Kernel Driver Service Installation
    description: Detects the installation of the NvFsFilter service associated with the BYOVD driver attack.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1543.003
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Search for the driver file nvfsflt64.sys across the enterprise
      owner: SOC
      due: 24h
      evidence: Source explicitly identifies nvfsflt64.sys as the malicious driver
  mitigation_plan:
    - priority: immediate
      action: Enable Microsoft's vulnerable driver blocklist
      owner: IT Operations
      addresses: BYOVD technique
      evidence: Microsoft's vulnerable driver blocklist is designed to mitigate the loading of abusable drivers
---

Since at least August 2026, threat actors have been distributing a sophisticated credential-stealer masquerading as the LastPass Authenticator tool via deceptive GitHub repositories. The campaign relies on search engine optimization to lure victims into downloading a ZIP archive padded with junk data to bypass file-size scanning limits. Upon execution, the malware utilizes DLL side-loading to gain system-level privileges and deploy a kernel-mode driver, identified by researchers as a renamed version of the CnCrypt 'CcProtect.sys' driver. Although the driver carries a legitimate Microsoft hardware compatibility signature, it is used to perform a 'Bring Your Own Vulnerable Driver' (BYOVD) attack, specifically targeting and terminating over 145 known security and EDR processes. Once security tools are incapacitated, the 'Rapuncel' stealer harvests saved credentials from browsers, cryptocurrency wallets, and session tokens for applications like Discord and Telegram. The attack maintains persistence by re-executing the driver and stealer upon system reboot.

## Attack Chain

1. Victim navigates to a fraudulent GitHub repository (e.g., github.com/LastPass-Authenticator) and downloads a malicious ZIP archive.
2. The archive is opened, exposing vsdbg.exe and a malicious vsdbg.dll, initiating a DLL side-loading sequence.
3. The loader executes multiple privilege escalation techniques to achieve SYSTEM-level access.
4. The installer deploys the kernel driver (e.g., nvfsflt64.sys) as a Windows service named 'NvFsFilter'.
5. The driver (Alinubx.sys/CcProtect.sys) loads into the kernel and parses an internal list of 145 security-related processes to terminate.
6. The 'Rapuncel' stealer extracts saved passwords from browser app-bound data and harvests session files for Discord, Steam, and Telegram.
7. Harvested data is compressed into a ZIP file and exfiltrated to an attacker-controlled command-and-control server.

## Impact

Victims experience full credential compromise including saved web passwords, cryptocurrency wallet seeds, and active session tokens for critical communication tools. Because the malware operates at the kernel level and proactively terminates security software, traditional detection and remediation tools are bypassed, necessitating a full system rebuild for infected machines.

## Recommendation

Prioritize the following actions for detection engineering and incident response:
- Deploy the Sigma rule below to detect the installation of the specific kernel driver service.
- Audit existing endpoints for the existence of the file C:\Windows\System32\drivers\nvfsflt64.sys.
- Monitor process creation logs for the execution of vsdbg.exe in suspicious working directories (non-standard paths).
- Enforce the use of Microsoft's vulnerable driver blocklist via Windows Defender Application Control (WDAC).
- Implement memory forensic analysis on hosts suspected of infection to identify the presence of the driver if standard EDR is disabled.
