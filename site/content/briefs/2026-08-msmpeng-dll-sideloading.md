---
title: REvil Ransomware DLL Side-Loading via Msmpeng.exe
slug: 2026-08-msmpeng-dll-sideloading
description: The REvil ransomware group employs DLL side-loading to bypass security controls by placing malicious 'msmpeng.exe' or 'mpsvc.dll' files in non-standard directories to execute payloads.
date: "2026-08-17T18:37:05Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - REvil
  - Sodinokibi
  - GOLD SOUTHFIELD
tags:
  - ransomware
  - persistence
  - defense-evasion
  - side-loading
vendors:
  - Microsoft
products:
  - Windows Defender
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1574
    technique_name: Hijack Execution Flow
    evidence: The REvil ransomware uses DLL side-loading to execute malicious payloads.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1574
    technique_name: Hijack Execution Flow
    evidence: This activity is significant because it is associated with the REvil ransomware, which uses DLL side-loading to execute malicious payloads.
    confidence_band: high
references:
  - https://community.sophos.com/b/security-blog/posts/active-ransomware-attack-on-kaseya-customers
rules:
  - title: Detect Msmpeng.exe or Mpsvc.dll Creation in Non-Default Paths
    description: Detects the creation of msmpeng.exe or mpsvc.dll outside of standard Windows Defender folders, indicating potential DLL side-loading for ransomware deployment.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1574.001
    data_sources:
      - file_event
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma detection rule for msmpeng/mpsvc file creation
      owner: Detection Engineering
      due: 24h
      evidence: Source documentation of REvil DLL side-loading TTP.
  mitigation_plan:
    - priority: short_term
      action: Review and harden file system permissions on high-risk directories
      owner: IT Operations
      addresses: T1574.001
      evidence: General security best practices for preventing DLL side-loading.
---

The REvil ransomware threat group leverages a DLL side-loading technique to achieve persistence and facilitate code execution. Attackers drop malicious versions of the Windows Defender binaries 'msmpeng.exe' (the Antimalware Service Executable) or 'mpsvc.dll' (the Antimalware Service Library) into unauthorized file system locations. By placing these files outside of the protected 'C:\\Program Files\\Windows Defender' or 'WinSxS' directories, the threat actor forces the operating system to load the malicious library instead of the legitimate one when the service is invoked. This tactic is used to evade security monitoring, as the malicious activity appears to originate from a trusted Microsoft binary. Successful exploitation allows for the deployment of ransomware, leading to broad data encryption, system compromise, and significant extortion risks. This behavior has been observed in campaigns targeting enterprise organizations.

## Attack Chain

1. The attacker gains initial access to the target environment via compromised credentials or exploit.
2. The attacker performs internal reconnaissance to identify writable directories outside of System32 or protected program paths.
3. The attacker drops a malicious library, 'mpsvc.dll', or a renamed executable, 'msmpeng.exe', into the identified writable directory.
4. The attacker establishes persistence by modifying registry keys or creating services to point to the malicious binary location.
5. The OS initiates the side-loading process when the malicious executable is triggered or the service is restarted.
6. The legitimate binary loads the malicious 'mpsvc.dll' from the attacker-controlled folder due to DLL search order hijacking.
7. The payload executes in the context of the high-privileged Antimalware Service process.
8. Final objective: Ransomware deployment, file encryption, and exfiltration of sensitive data.

## Impact

Successful execution of this attack leads to the deployment of the REvil ransomware payload. The impact includes the encryption of critical business data, full system compromise, exfiltration of sensitive corporate information, and the threat of double extortion. Historical attacks associated with this technique have resulted in the disruption of critical infrastructure and widespread business outages.

## Recommendation

1. Enable Sysmon Event ID 11 (FileCreate) across the endpoint fleet to identify suspicious file creation events.
2. Deploy the Sigma rules below to monitor for 'msmpeng.exe' or 'mpsvc.dll' creation events in unauthorized paths.
3. Use EDR solutions to alert on child processes spawned by instances of 'msmpeng.exe' that deviate from standard behavior.
4. Restrict write permissions on directories that are commonly used for side-loading, such as temporary folders or user-writable application data paths.
