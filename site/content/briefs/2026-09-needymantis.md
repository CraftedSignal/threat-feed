---
title: NeedyMantis Modular Post-Compromise Framework
slug: 2026-09-needymantis
description: NeedyMantis is a modular, multi-stage malware framework used by threat actors like Storm-3069 to establish persistence and perform follow-on operations via DLL sideloading and custom encrypted archives.
date: "2026-09-28T16:17:15Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - Storm-3069
tags:
  - persistence
  - defense-evasion
  - post-compromise
  - modular-malware
  - storm-3069
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1574.002
    technique_name: DLL Side-Loading
    evidence: The loader and archive have been found packaged alongside legitimate software, with the first-stage loader—masquerading as a required DLL—being loaded through DLL sideloading.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1027
    technique_name: Obfuscated Files or Information
    evidence: The loader employs common anti-analysis techniques to hinder analysis, like obfuscating most of its important strings.
    confidence_band: high
iocs:
  - type: hash_sha256
    value: e842dd7642c8e04b5ec20b6393848a9c904e4832930950c16664fe7800ba382e
  - type: hash_sha256
    value: 9cb68f986043a576e19d32184c583b7d8f571c7219d8dc0065dced1c13f077ef
ioc_counts:
  hash_sha256: 2
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Block documented hashes on all endpoints
      owner: SOC
      due: 24h
      evidence: Source provides confirmed malicious SHA-256 hashes.
  hunt_leads:
    - lead: Search for files with expected malicious names in non-standard ProgramData or ProgramFiles subdirectories
      technique_id: T1574.002
      data_needed:
        - File creation events
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source lists specific paths like %ProgramData%\office\dbghelp.dll used in intrusions.
  mitigation_plan:
    - priority: immediate
      action: Remove unauthorized files found in monitored application directories
      owner: IT Operations
      addresses: NeedyMantis framework
      evidence: The malware framework uses DLL sideloading from application directories.
---

NeedyMantis is a modular post-compromise malware framework identified by Microsoft Threat Intelligence, primarily used to maintain long-term access in victim environments. First observed in October 2025, the malware is typically deployed in the post-compromise stage of an intrusion, meaning the initial access vector is variable and independent of the NeedyMantis framework itself. Targeted sectors include telecommunications, universities, medical nonprofits, and government contractors. 

The framework is highly modular, employing a first-stage loader and encrypted file archives, often packaged alongside legitimate software. It leverages DLL sideloading to execute by masquerading as components from software like Poedit, curl, and Vim, or by spoofing system DLLs associated with Microsoft, Broadcom, Intel, and NVIDIA. NeedyMantis utilizes x64 shellcode, dynamic API resolution, and obfuscated stack strings to evade detection. The framework's design supports the deployment of additional modules to extend capabilities, making it a persistent and adaptable tool for targeted operations linked to threat actors operating from China.

## Attack Chain

1. Attacker establishes initial access via an undisclosed vector (e.g., supply chain compromise).
2. Attacker uses post-exploitation tools (e.g., Impacket) to copy legitimate software, a malicious DLL loader, and a custom file archive to the target device.
3. Attacker triggers the execution of the legitimate software, which leads to the sideloading of the malicious DLL (e.g., WinSparkle.dll).
4. The first-stage loader resolves Windows APIs dynamically and deobfuscates stack strings.
5. The loader decrypts and extracts the second-stage component from the accompanying file archive.
6. The second-stage loader initializes the modular framework.
7. The framework connects to C2 infrastructure to receive commands or additional malicious modules.
8. Attacker performs follow-on operations such as lateral movement or exfiltration.

## Impact

Successful deployment of NeedyMantis provides an attacker with persistent, long-term access to sensitive environments. Observed victims include critical infrastructure providers, governmental organizations, and educational institutions. The framework's modularity enables attackers to tailor their activities for espionage or further malicious operations, potentially resulting in data exfiltration or the compromise of additional systems within the targeted network.

## Recommendation

1. Block and hunt for the file hashes of observed NeedyMantis loaders and archives in the IOC list.
2. Implement detection rules for DLL sideloading behavior involving the specified DLL names (e.g., WinSparkle.dll, libcurl.dll, vim64.dll) when executed from non-standard application paths.
3. Monitor for the creation of files matching the known malicious DLL and archive naming patterns (e.g., %ProgramData%\office\dbghelp.dll) on enterprise endpoints.
4. Use EDR telemetry to audit process creation events where legitimate software (e.g., Poedit, Vim, curl) spawns suspicious child processes or loads unexpected DLLs from the application directory.
