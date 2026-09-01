---
title: Detection of CMSTP App Paths Registry Modification
slug: 2026-09-cmstp-registry
description: Adversaries leverage the Microsoft Connection Manager Profile Installer (CMSTP) via registry modifications to achieve arbitrary code execution or bypass User Account Control (UAC).
date: "2026-09-01T12:07:17Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - execution
  - persistence
  - privesc
  - lolbas
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1218
    technique_name: System Binary Proxy Execution
    evidence: The technique involves manipulating specific registry keys within the App Paths hive, which influences how the operating system handles execution requests or loads associated dynamic link libraries.
    confidence_band: high
references:
  - https://lolbas-project.github.io/lolbas/Binaries/Cmstp/
  - https://web.archive.org/web/20190720093911/http://www.endurant.io/cmstp/detecting-cmstp-enabled-code-execution-and-uac-bypass-with-sysmon/
rules:
  - title: CMSTP App Paths Registry Key Modification
    description: Detects modifications to the CMSTP App Paths registry key indicating potential abuse for arbitrary code execution or UAC bypass.
    platform: sigma
    severity: high
    tactics:
      - execution
      - stealth
    techniques:
      - T1218.003
    data_sources:
      - registry_set
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the Sigma rule to monitor registry modifications in the App Paths hive for cmmgr32.exe
      owner: Detection Engineering
      due: 48h
      evidence: Source rule b6d235fc-1d38-4b12-adbe-325f06728f37
  hunt_leads:
    - lead: Search historical registry modification logs for write operations to HKLM or HKCU under \App Paths\cmmgr32.exe\
      technique_id: T1218.003
      data_needed:
        - Registry Set (Event ID 12/13)
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Registry key abuse is a known indicator of CMSTP exploitation
---

Microsoft Connection Manager Profile Installer (CMSTP.exe) is a legitimate Windows binary designed to install Connection Manager service profiles. Threat actors frequently abuse this utility to execute arbitrary code or bypass UAC. The technique involves manipulating specific registry keys within the App Paths hive, which influences how the operating system handles execution requests or loads associated dynamic link libraries (DLLs). By modifying these registry paths, attackers can force CMSTP to load malicious DLLs or configuration files, facilitating execution in a higher-privileged context. This is a well-documented LOLBAS (Living Off the Land Binary and Script) technique that persists across modern Windows environments, requiring defenders to monitor registry modifications associated with CMSTP's configuration parameters.

## Attack Chain

1. Attacker identifies a target system where CMSTP.exe execution is permissible.
2. Attacker prepares a malicious DLL or configuration profile (INF file) to be loaded by CMSTP.
3. Attacker gains sufficient privileges to modify the Windows registry.
4. Attacker performs a write operation to the registry key HKLM or HKCU under Software\Microsoft\Windows\CurrentVersion\App Paths\cmmgr32.exe\.
5. Attacker executes cmstp.exe via command line or automated script.
6. CMSTP.exe references the modified App Paths registry key.
7. CMSTP.exe loads the attacker-supplied DLL or INF file, bypassing security controls or executing arbitrary logic.
8. Final objective is achieved, such as privilege escalation, persistence, or payload execution.

## Impact

Successful abuse of this technique allows an attacker to execute code with elevated privileges, bypassing standard UAC protections. This facilitates further post-exploitation activities, including credential dumping, lateral movement, or the deployment of ransomware within an organization.

## Recommendation

1. Deploy the provided Sigma rule to monitor registry modifications targeting cmmgr32.exe App Paths.
2. Alert on any write operations to the registry path SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\cmmgr32.exe\ that are not associated with authorized system updates.
3. Utilize Sysmon or native Windows Registry auditing to capture the process ID responsible for the registry change, ensuring attribution back to the parent process.
