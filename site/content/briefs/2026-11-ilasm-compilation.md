---
brief_id: brief-2026-11-25-ilasm-compilation
event_id: brief-2026-11-25-ilasm-compilation
revision: 1
activity_at: "2026-11-25T16:27:57Z"
title: 'Living off the Land: C# IL Code Compilation via Ilasm.EXE'
slug: 2026-11-ilasm-compilation
description: The native Windows binary 'ilasm.exe' can be abused by adversaries as a proxy to compile intermediate language code into executables or DLLs, potentially bypassing security controls.
date: "2026-11-25T16:27:57Z"
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
tags:
  - defense-evasion
  - execution
  - lolbas
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1127
    technique_name: Trusted Developer Utilities Proxy Execution
    evidence: Ilasm.exe is a known binary used in Trusted Developer Utilities Proxy Execution (LOLBAS).
references:
  - https://lolbas-project.github.io/lolbas/Binaries/Ilasm/
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_ilasm_il_code_compilation.yml
rules:
  - title: C# IL Code Compilation Via Ilasm.EXE
    description: Detects the use of "Ilasm.EXE" in order to compile C# intermediate (IL) code to EXE or DLL.
    platform: sigma
    severity: medium
    tactics:
      - execution
      - stealth
    techniques:
      - T1127
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: monitor_or_close
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma rule to monitor for ilasm.exe usage with /dll or /exe flags.
---

## Overview
Ilasm.exe (IL Assembler) is a component of the .NET Framework designed to assemble intermediate language (IL) files into executable files (EXE) or dynamic link libraries (DLL). Adversaries utilize this binary as a "Living off the Land" (LotL) technique to compile code directly on a target system without requiring the installation of standard development tools.

## Impact
By leveraging this built-in utility, an adversary can create custom binaries post-compromise, which may facilitate the execution of arbitrary code.

## Recommendation
Detection teams should monitor for the execution of 'ilasm.exe' with command-line arguments that indicate file compilation, specifically looking for the '/dll' or '/exe' flags.
