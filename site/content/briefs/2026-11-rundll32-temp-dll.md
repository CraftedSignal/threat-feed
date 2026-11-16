---
brief_id: brief-2026-11-16-rundll32-temp-dll
event_id: brief-2026-11-16-rundll32-temp-dll
revision: 1
activity_at: "2026-11-16T04:20:29Z"
title: Windows Rundll32 loading DLLs from temporary directories
slug: 2026-11-rundll32-temp-dll
description: This detection monitors for the execution of rundll32.exe from temporary directories, a technique used to stage or execute malicious payloads and evade security controls.
date: "2026-11-16T04:20:29Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: roughly even chance
tags:
  - defense-evasion
  - initial-access
  - privilege-escalation
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
    subtechnique_id: T1218.011
    subtechnique_name: Rundll32
    evidence: While rundll32.exe is a legitimate Windows utility used to execute functions exported from DLLs, its use to load libraries from temporary locations is highly suspicious.
    confidence_band: high
references:
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/windows_rundll32_load_dll_in_temp_dir.yml
  - https://blog.sekoia.io/interlock-ransomware-evolving-under-the-radar/
rules:
  - title: Windows Rundll32 Load DLL in Temp Dir
    description: This detection identifies instances where rundll32.exe is used to load a DLL from a temporary directory, such as C:\Users\<User>\AppData\Local\Temp\ or C:\Windows\Temp\.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1218.011
    data_sources:
      - process_creation
      - windows
      - sysmon
rules_count: 1
---

## Overview

Security teams should monitor for the execution of the native Windows binary rundll32.exe when it loads dynamic link libraries (DLLs) from temporary system paths, such as 'C:\Users\&lt;User>\AppData\Local\Temp\' or 'C:\Windows\Temp\'. While rundll32.exe is a legitimate component for executing functions from DLLs, its use to load libraries from temporary locations is highly suspicious. These directories are commonly used by malware and red team tools to stage payloads or execute code in-memory, avoiding persistent locations.

## Impact

This behavior is often associated with defense evasion, initial access, or privilege escalation. Loading DLLs from temporary paths is a high-fidelity indicator, particularly when the DLL is unsigned, recently written, or executed shortly after a download.

## Recommendation

Implement process-creation monitoring focusing on the command-line parameters of rundll32.exe to detect library loading from temporary directories. Ensure that telemetry captures the process GUID, process name, parent process, and full command-line arguments to facilitate investigation.
