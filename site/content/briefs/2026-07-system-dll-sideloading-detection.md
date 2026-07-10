---
title: Potential System DLL Sideloading From Non System Locations
slug: 2026-07-system-dll-sideloading-detection
description: This brief describes a common defense evasion technique where malicious actors bypass security controls by loading legitimate system DLLs from non-standard directories, enabling arbitrary code execution within trusted processes.
date: "2026-07-10T13:59:41Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - dll-sideloading
  - windows
  - defense-evasion
  - execution
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1574
    technique_name: Hijack Execution Flow
    evidence: Detects DLL sideloading of DLLs usually located in system locations (System32, SysWOW64, etc.) when loaded from non-standard paths.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1574
    technique_name: Hijack Execution Flow
    evidence: DLL sideloading allows for malicious code execution by causing a legitimate application to load a malicious library instead of the intended one.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1574
    technique_name: Hijack Execution Flow
    evidence: DLL sideloading is a common defense evasion and execution technique... This technique allows attackers to hijack the loading process... for persistence, privilege escalation.
    confidence_band: med
references:
  - https://hijacklibs.net/
  - https://blog.cyble.com/2022/07/21/qakbot-resurfaces-with-new-playbook/
  - https://blog.cyble.com/2022/07/27/targeted-attacks-being-carried-out-via-dll-sideloading/
  - https://github.com/XForceIR/SideLoadHunter/blob/cc7ef2e5d8908279b0c4cee4e8b6f85f7b8eed52/SideLoads/README.md
  - https://www.hexacorn.com/blog/2023/12/26/1-little-known-secret-of-runonce-exe-32-bit/
  - https://www.sophos.com/en-us/blog/finding-minhook-in-a-sideloading-attack-and-sweden-too
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_side_load_from_non_system_location.yml
rules:
  - title: Potential System DLL Sideloading From Non System Locations
    description: Detects DLL sideloading of DLLs usually located in system locations (System32, SysWOW64, etc.) when loaded from non-standard paths.
    platform: sigma
    severity: medium
    tactics:
      - execution
      - persistence
      - privilege_escalation
      - stealth
    techniques:
      - T1574.001
    data_sources:
      - image_load
      - windows
rules_count: 1
---

DLL sideloading is a pervasive defense evasion and execution technique utilized by malicious actors to achieve arbitrary code execution within the context of legitimate applications. This method involves placing a specially crafted or legitimate-but-misplaced DLL file in a directory that a trusted application searches before locating its intended system library. When the application launches, it inadvertently loads the attacker-controlled DLL, leading to the execution of malicious code. This technique can be employed for various purposes, including persistence, privilege escalation, and bypassing security mechanisms that trust the legitimate application. Prominent malware families such as QakBot and Dridex have been observed leveraging DLL sideloading, often utilizing common system DLLs like `WindowsCodecs.dll` or `iphlpapi.dll`. The detection rule provided herein specifically targets instances where typical Windows system DLLs, usually found in directories such as System32 or SysWOW64, are loaded from unusual or user-controlled locations, indicating potential compromise.

## Impact

The successful exploitation of DLL sideloading can result in significant operational disruption and data compromise. By injecting malicious code into legitimate processes, attackers can achieve elevated privileges, establish persistent access to systems, and evade detection by security software. This provides a versatile vector for further stages of an attack, such as data exfiltration, deployment of additional malware, or complete system takeover. The consequences range from compromised individual workstations to severe network-wide breaches, depending on the initial access vector and the targeted system's role within the organization. Early detection and mitigation of DLL sideloading are critical to prevent attackers from escalating privileges or achieving their final objectives.

## Recommendation

* Deploy the Sigma rule "Potential System DLL Sideloading From Non System Locations" to your Security Information and Event Management (SIEM) system and tune it for your specific environment.
* Ensure that `image_load` logging for Windows endpoints is fully enabled to provide the necessary telemetry for the rule described in this brief.
* Regularly review `image_load` events for the specific DLLs listed in the Sigma rule that are loaded from non-standard paths, prioritizing investigation of alerts originating from critical infrastructure.
