---
title: Unsigned DLL Loaded by Svchost for Persistence and Privilege Escalation
slug: 2024-01-unsigned-dll-svchost
description: Adversaries may load unsigned DLLs into svchost.exe to establish persistence or escalate privileges, leveraging a shared Windows service to execute malicious code with elevated permissions.
date: "2024-01-09T18:30:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - defense-evasion
  - execution
  - windows
  - dll-injection
vendors:
  - Elastic
products:
  - Elastic Defend
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1543
    technique_name: Create or Modify System Process
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1574
    technique_name: Hijack Execution Flow
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1569
    technique_name: System Services
references:
  - https://www.elastic.co/security-labs/Hunting-for-Suspicious-Windows-Libraries-for-Execution-and-Evasion
  - https://attack.mitre.org/techniques/T1543/
  - https://attack.mitre.org/techniques/T1543/003/
  - https://attack.mitre.org/techniques/T1574/
  - https://attack.mitre.org/techniques/T1574/011/
  - https://attack.mitre.org/techniques/T1036/
  - https://attack.mitre.org/techniques/T1036/001/
  - https://attack.mitre.org/techniques/T1569/
  - https://attack.mitre.org/techniques/T1569/002/
iocs:
  - type: hash_sha256
    value: 3ed33e71641645367442e65dca6dab0d326b22b48ef9a4c2a2488e67383aa9a6
  - type: hash_sha256
    value: b4db053f6032964df1b254ac44cb995ffaeb4f3ade09597670aba4f172cf65e4
  - type: hash_sha256
    value: 214c75f678bc596bbe667a3b520aaaf09a0e50c364a28ac738a02f867a085eba
  - type: hash_sha256
    value: 23aa95b637a1bf6188b386c21c4e87967ede80242327c55447a5bb70d9439244
  - type: hash_sha256
    value: 5050b025909e81ae5481db37beb807a80c52fc6dd30c8aa47c9f7841e2a31be7
ioc_counts:
  hash_sha256: 5
rules:
  - title: Unsigned DLL Loaded by Svchost
    description: Detects the loading of an unsigned DLL by svchost.exe from unusual paths.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - execution
      - persistence
    techniques:
      - T1036.001
      - T1543.003
      - T1569.002
      - T1574.011
    data_sources:
      - image_load
      - windows
  - title: Suspicious DLL Creation and Svchost Load
    description: Detects recently created DLLs loaded by svchost, indicating potential malicious DLL injection.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - execution
      - persistence
    techniques:
      - T1036.001
      - T1543.003
      - T1569.002
      - T1574.011
    data_sources:
      - image_load
      - windows
rules_count: 2
---

Attackers may attempt to load malicious, unsigned DLLs into `svchost.exe`, a legitimate Windows service host process, to maintain persistence or escalate privileges. This technique abuses the shared service host process to execute arbitrary code with SYSTEM privileges. The `svchost.exe` process, which typically hosts multiple Windows services, can be targeted to load malicious DLLs from unusual file paths, potentially bypassing security measures that rely on code signing validation. This is especially concerning because `svchost.exe` is a trusted process, making detection more challenging. The loading of unsigned DLLs by `svchost.exe` from atypical directories is a strong indicator of potential malicious activity, as legitimate Windows services rarely load unsigned libraries from such locations.

## Attack Chain

1.  An adversary gains initial access to the system through an undisclosed method (e.g., exploitation of a vulnerability or social engineering).
2.  The attacker creates a malicious, unsigned DLL on the compromised system in a non-standard directory like `C:\ProgramData\`.
3.  The attacker modifies the Windows Registry to configure a service hosted by `svchost.exe` to load the malicious DLL. This often involves manipulating service dependencies or service parameters.
4.  The system is restarted, or the targeted service is manually restarted, causing `svchost.exe` to load the specified DLL.
5.  `svchost.exe` executes the code within the malicious DLL, now running with the privileges of the hosted service (typically SYSTEM).
6.  The malicious DLL performs actions such as installing backdoors, escalating privileges further, or establishing command and control (C2) communication.
7.  The attacker uses the established C2 channel to remotely control the compromised system, exfiltrate data, or perform other malicious activities.
8.  The attacker maintains persistence on the system by ensuring the malicious DLL is loaded each time the service or system starts.

## Impact

Successful exploitation allows attackers to gain persistent access to the compromised system with elevated (SYSTEM) privileges. This can lead to complete system compromise, data theft, installation of backdoors, and lateral movement within the network. The use of `svchost.exe` as a host for malicious DLLs makes detection more difficult, allowing attackers to operate undetected for extended periods.

## Recommendation

*   Implement the provided Sigma rule to detect unsigned DLLs loaded by `svchost.exe`, focusing on the specified file paths and code signature status.
*   Examine `dll.Ext.relative_file_creation_time` to identify DLLs created shortly before being loaded to catch newly created malicious files.
*   Review and validate the legitimacy of all DLLs loaded by `svchost.exe`, focusing on those located in unusual paths.
*   Update endpoint detection and response (EDR) systems to specifically monitor for the loading of unsigned DLLs by system processes like `svchost.exe`.
*   Continuously update the exclusion list of known good DLL hashes to reduce false positives.
