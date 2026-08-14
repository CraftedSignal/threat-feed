---
title: HoneyMyte CoolClient Backdoor Updated with Kernel-Mode Rootkit
slug: 2026-08-coolclient-rootkit
description: The HoneyMyte APT group has enhanced its CoolClient backdoor with a custom kernel-mode driver that hides malicious artifacts and activity from security software on Windows systems.
date: "2026-08-14T14:03:05Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - HoneyMyte
tags:
  - backdoor
  - rootkit
  - apt
  - windows
  - espionage
vendors:
  - Sangfor
products:
  - Endpoint Secure
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: Before deploying the malware, the actor added both a folder exclusion and a file exclusion to Microsoft Defender.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
    evidence: Persistence was established through a scheduled task that launched defender.exe with SYSTEM privileges during system startup.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1014
    technique_name: Rootkit
    evidence: The newest CoolClient variant can deploy a signed kernel-mode driver as a Windows service... to hide malicious processes, files, and registry entries.
    confidence_band: high
references:
  - https://securelist.com/honeymyte-coolclient-driver-rootkit/121028/
rules:
  - title: Detect Suspicious Microsoft Defender Exclusion via WMI
    description: Detects usage of wmic to add exclusions to Microsoft Defender, a technique observed to facilitate CoolClient deployment.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
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
    - action: Deploy WMI exclusion detection rule to SIEM.
      owner: Detection Engineering
      due: 24h
      evidence: Source explicitly documents WMI usage for Defender exclusion evasion.
  hunt_leads:
    - lead: Search for existence of files named loadcert.ini, cert.ini, time.ini, or libngs.dll in non-standard locations.
      technique_id: T1005
      data_needed:
        - File system audit logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: These are primary components of the CoolClient backdoor.
  mitigation_plan:
    - priority: immediate
      action: Restrict local administrative rights to prevent unauthorized service and driver installation.
      owner: IT Operations
      addresses: Kernel-mode rootkit installation
      evidence: Malware relies on system privileges to install the kernel-mode driver.
---

The HoneyMyte APT group (also known as Mustang Panda) has significantly upgraded its CoolClient backdoor, introducing a kernel-mode rootkit driver to enhance stealth. The updated malware utilizes DLL sideloading via legitimate Sangfor executables to achieve initial execution and persistence. The most notable evolution is the deployment of a signed kernel-mode driver, which acts as a Windows service and communicates with the user-mode backdoor via IOCTL requests. This driver provides rootkit capabilities, specifically hiding malicious processes, files, and registry entries from security tools and analysts.

The intrusion chain involves the use of PlugX as an initial post-compromise implant to facilitate the deployment of CoolClient components. The threat actor actively modifies Microsoft Defender exclusions to evade detection before establishing persistence through scheduled tasks running with SYSTEM privileges. The malware continues its multi-stage loading process, involving heavily obfuscated components that decrypt and execute the final-stage C2 implant, now renamed to 'cert.ini'. This update, observed in intrusions across Asia, signifies a shift toward deeper kernel-level integration for long-term espionage operations.

## Attack Chain

1. Initial access is gained using a PlugX implant to download and stage CoolClient components.
2. The actor adds directory and file exclusions to Microsoft Defender using 'wmic' to allow the malicious 'defender.exe' (a renamed Sangfor executable) to run undetected.
3. A scheduled task is created under the name 'Microsoft\Windows\Windows Defender Advanced Threat Protection Service' to execute 'defender.exe' with SYSTEM privileges at startup.
4. 'defender.exe' performs DLL sideloading by loading the malicious 'libngs.dll'.
5. 'libngs.dll' executes its DllMain routine to decrypt and load 'loadcert.ini' into memory.
6. The second-stage loader 'loadcert.ini' decrypts 'time.ini', deploys the kernel-mode driver as a Windows service, and injects the final-stage 'cert.ini' implant into 'synchost.exe'.
7. The driver enables rootkit features by intercepting and filtering system calls via IOCTL requests to mask the presence of CoolClient.
8. The final-stage implant establishes C2 communication to perform espionage activities.

## Impact

The updated CoolClient backdoor allows HoneyMyte to maintain persistent, long-term access to compromised systems in Asia, including Pakistan, Mongolia, and Myanmar. The kernel-mode rootkit significantly hampers incident response and forensic analysis by concealing the malware's footprint, potentially leading to prolonged undetected data exfiltration and cyber-espionage.

## Recommendation

1. Deploy Sigma rules to detect the creation of suspicious Microsoft Defender exclusions via WMI.
2. Monitor scheduled tasks for entries that execute binaries from non-standard or unauthorized directories, specifically targeting the identified 'Windows Defender' folder path masquerading.
3. Implement endpoint detection for unauthorized loading of kernel drivers, specifically focusing on drivers not signed by known, trusted vendors.
4. Hunt for the presence of the identified CoolClient component filenames ('loadcert.ini', 'cert.ini', 'time.ini', 'libngs.dll') within the environment.
5. Audit system services and drivers for unexpected additions or modifications, particularly those interacting with legitimate process names like 'synchost.exe'.
