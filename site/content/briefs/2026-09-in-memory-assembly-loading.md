---
title: Detection of In-Memory Assembly Loading via PowerShell Reflection
slug: 2026-09-in-memory-assembly-loading
description: This brief documents the use of .NET reflection techniques within PowerShell to execute arbitrary code in-memory, a method frequently utilized to bypass file-based security controls.
date: "2026-09-03T13:38:14Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - windows
  - powershell
  - stealth
  - in-memory
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1620
    technique_name: Reflective Code Loading
    evidence: Detects usage of Reflection.Assembly load functions to dynamically load assemblies in memory
    confidence_band: high
rules:
  - title: Detect Potential In-Memory Execution via Reflection.Assembly
    description: Detects usage of [Reflection.Assembly]::Load functions in PowerShell scripts to dynamically load assemblies in memory.
    platform: sigma
    severity: medium
    tactics:
      - stealth
    techniques:
      - T1620
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
    - action: Enable PowerShell Script Block Logging (Event ID 4104) across all endpoints
      owner: IT Operations
      due: 72h
      evidence: Required for observability into in-memory assembly loading
  hunt_leads:
    - lead: Search for instances of [Reflection.Assembly] in Script Block logs
      technique_id: T1620
      data_needed:
        - Event ID 4104
      priority: high
      confidence: high
      disposition: convert_to_detection
      evidence: Common pattern for fileless execution
  mitigation_plan:
    - priority: medium_term
      action: Enforce Constrained Language Mode (CLM) via AppLocker or WDAC
      owner: Security Engineering
      addresses: T1620
      evidence: CLM restricts the use of sensitive .NET types including Reflection
---

The use of .NET reflection via PowerShell enables attackers to load .NET assemblies directly from memory, effectively executing malicious binaries without writing them to disk. This technique leverages the `[Reflection.Assembly]::Load` or `[Reflection.Assembly]::LoadFrom` methods to bypass traditional file-based detection mechanisms and endpoint security products that monitor file system changes. By executing code entirely in the memory space of a PowerShell process, adversaries can maintain stealth and reduce their forensic footprint on the host. This behavior is commonly observed during the post-exploitation phase, where attackers load secondary payloads, custom tools, or offensive frameworks. Defenders must monitor PowerShell Script Block Logging to capture the execution of these reflection methods, as they are not visible via standard file-creation events.

## Attack Chain

1. An attacker gains initial execution on a target system, often via a spearphishing attachment or exploited web vulnerability.
2. The attacker launches a PowerShell process to execute commands within the victim's environment.
3. The attacker fetches a malicious .NET assembly (e.g., a DLL or EXE) from a remote URL or reads it from a hidden encoded string in the initial script.
4. The attacker uses the `[System.Reflection.Assembly]::Load()` method within a PowerShell script block to load the binary into the active process's memory.
5. Once loaded, the attacker calls methods or classes from the malicious assembly to execute its payload.
6. The malicious payload performs its objective, such as credential theft, lateral movement, or data exfiltration.
7. The process terminates or continues to reside in memory, leaving minimal evidence on the disk.

## Impact

Successful exploitation allows for fileless execution of arbitrary code, significantly complicating incident response and forensic analysis. This technique is often used to launch offensive tooling, such as Cobalt Strike beacons or custom post-exploitation kits, which can lead to full environment compromise and sensitive data exfiltration if not detected and blocked.

## Recommendation

Prioritize the implementation of robust monitoring for PowerShell activity across all enterprise endpoints to detect suspicious reflection-based execution.

* Enable PowerShell Script Block Logging (Event ID 4104) across all Windows endpoints to capture the full command structure, including reflection methods.
* Deploy the provided Sigma rule to identify script blocks utilizing `[Reflection.Assembly]::load`.
* Review any identified PowerShell execution for context, as administrative scripts may utilize these methods for legitimate software deployment or system management.
