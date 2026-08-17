---
title: Mustang Panda Deploys Signed Kernel-Mode Rootkit with CoolClient Backdoor
slug: 2026-08-mustang-panda-coolclient-rootkit
description: The threat actor HoneyMyte (Mustang Panda) is utilizing a signed kernel-mode rootkit named msagent.sys to provide stealth capabilities for its CoolClient backdoor, facilitating process, file, and network hiding on compromised Windows systems.
date: "2026-08-17T11:46:20Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - HoneyMyte
tags:
  - rootkit
  - backdoor
  - espionage
  - windows
  - malware
products:
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547.001
    technique_name: Registry Run Keys / Startup Folder
    evidence: The second-stage malware creates an AutoRun registry entry named goopdate and can install a Windows service named media_updaten.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1574.002
    technique_name: DLL Side-Loading
    evidence: Execution begins when the legitimate Sangfor application loads a malicious libngs.dll
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562.001
    technique_name: Disable or Modify Tools
    evidence: The rootkit registers filesystem, registry, process, object, and image-load callbacks that use these entries when handling activity on the infected Windows system.
    confidence_band: high
iocs:
  - type: hash_md5
    value: 2d7c8780e97409770a9d4f31c66c9d63
  - type: hash_md5
    value: 9460e150e1981d5c165043520c5c12fe
  - type: hash_md5
    value: 9717f005c5fb98e08d2ad983d88f94ee
  - type: hash_md5
    value: f518d8e5fe70d9090f6280c68a95998f
ioc_counts:
  hash_md5: 4
action_plan:
  priority: elevated
  owners:
    - SOC
    - CTI
  immediate_actions:
    - action: Block identified MD5 file hashes in EDR/AV solutions
      owner: SOC
      due: 24h
      evidence: Kaspersky identified these indicators as malicious components
  hunt_leads:
    - lead: Search for non-standard services named 'msagent' or 'media_updaten'
      technique_id: T1543.003
      data_needed:
        - System event logs / service creation logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Rootkit is installed as a Windows service named msagent
  mitigation_plan:
    - priority: immediate
      action: Restrict SeTcbPrivilege assignments to authorized service accounts
      owner: IT Operations
      addresses: Kernel-mode driver deployment
      evidence: Driver is deployed when CoolClient has full access to the Service Control Manager and SeTcbPrivilege
---

The threat actor HoneyMyte (also known as Mustang Panda) has been observed enhancing its CoolClient backdoor with a sophisticated, signed Windows kernel-mode rootkit, identified as msagent.sys. This rootkit provides deep stealth capabilities, including the ability to hide processes, files, registry objects, and C2 network information from security tools. The driver is deployed when the malware gains sufficient privileges (Service Control Manager access and SeTcbPrivilege) during the post-compromise phase. This development represents a significant evolution in the group's evasion tactics, allowing the backdoor to maintain persistence and protect its presence on infected systems in Myanmar, Mongolia, Pakistan, and Russia. The rootkit leverages kernel notification callbacks and hooks within the Nsiproxy driver to filter system-level activity, indicating a high level of technical proficiency and commitment to long-term espionage.

## Attack Chain

1. Initial access is achieved via a primary implant, typically PlugX, which prepares the environment.
2. The actor creates a fake Windows Defender installation directory and deploys a legitimate, renamed Sangfor executable to facilitate DLL sideloading.
3. Persistence is established via a scheduled task that executes the renamed defender.exe with SYSTEM privileges at startup.
4. The legitimate binary loads a malicious libngs.dll, which decrypts and executes the second-stage component loadcert.ini.
5. The second-stage component performs UAC bypass and process injection, eventually injecting into a legitimate process such as synchost.exe.
6. If adequate privileges are met, the malware extracts and drops the signed msagent.sys driver to the disk.
7. The driver is installed as a Windows service named 'msagent' and communicates with the user-mode CoolClient via IOCTL requests (e.g., 0x222120, 0x2221E0, 0x2220F0) to register protected paths and C2 information.
8. Final-stage activity involves keylogging, clipboard theft, and C2 communication, all protected by the kernel-mode rootkit.

## Impact

HoneyMyte's use of this rootkit significantly complicates incident response and detection efforts. By unlinking processes from the active process list and filtering network information at the Nsiproxy level, the malware effectively blinds traditional endpoint security tools. Confirmed victims include government entities across several regions, suggesting a focus on long-term espionage and sensitive data exfiltration.

## Recommendation

* Monitor for the installation of new kernel-mode drivers using Sigma rules tracking service creation where the binary is not part of a known-good software update cycle.
* Utilize the provided MD5 hashes to hunt for the identified msagent.sys and libngs.dll files in disk forensic images.
* Audit scheduled tasks and services for atypical binaries renamed to mimic system or legitimate vendor executables (e.g., 'defender.exe' in custom directories).
* Enable and aggregate kernel-level telemetry (e.g., Microsoft-Windows-Kernel-Driver event logs) to identify the registration of new driver services.
* Deploy detections for suspicious IOCTL communication patterns originating from user-mode processes to kernel-mode drivers, focusing on the identified IOCTL codes.
