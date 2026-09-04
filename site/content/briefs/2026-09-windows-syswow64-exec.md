---
title: Detection of Anomalous Cross-Architecture Process Execution
slug: 2026-09-windows-syswow64-exec
description: This brief covers the detection of an anomalous execution pattern where 32-bit processes in SysWOW64 launch 64-bit binaries in System32, a technique frequently used for privilege escalation and evasion.
date: "2026-09-04T18:02:07Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - anomaly
  - privilege-escalation
  - defense-evasion
  - execution
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1036
    technique_name: Masquerading
    evidence: The analytic detects an unusual process execution pattern where a process running from C:\Windows\SysWOW64\ attempts to execute a binary from C:\Windows\System32\.
    confidence_band: high
rules:
  - title: Detect Unusual SysWOW64 Process Launching System32 Binary
    description: Detects a 32-bit process from SysWOW64 spawning a 64-bit binary from System32, often indicative of evasion or privilege escalation.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1036.009
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy the provided Sigma rule to identify cross-architecture process spawning
      owner: Detection Engineering
      due: 48h
  mitigation_plan:
    - priority: medium_term
      action: Tune detection rules against internal software baseline to suppress false positives
      owner: SOC
---

This threat brief focuses on an anomalous execution pattern where a 32-bit process residing in C:\Windows\SysWOW64\ initiates a 64-bit executable located in C:\Windows\System32\. In standard Windows environments, 32-bit processes are expected to interact primarily with 32-bit binaries within their own directory structure. 

Deviation from this norm, specifically the invocation of 64-bit System32 binaries by a SysWOW64 parent process, is a known technique utilized by threat actors for process injection, privilege escalation, evasion, and unauthorized execution hijacking. Security teams should monitor for this pattern, particularly when the spawning process is unsigned, unusual, or associated with known malicious activity, as seen in campaigns attributed to actors such as those behind DarkGate and Salt Typhoon. While software updaters and compatibility tools may trigger this, the anomaly is a high-fidelity signal for hunting potential post-exploitation movement.

## Attack Chain

1. Attacker achieves initial execution of a 32-bit malicious binary dropped in C:\Windows\SysWOW64\.
2. The malicious 32-bit process identifies a target 64-bit binary in C:\Windows\System32\ for hijacking or escalation.
3. The 32-bit process spawns the 64-bit binary, crossing the architecture boundary.
4. The 64-bit binary is either executed directly or manipulated via process injection (e.g., remote thread injection).
5. The attacker gains the capability to operate within the 64-bit address space of the target process.
6. Attacker leverages the higher-privilege or 64-bit context to perform further reconnaissance, credential dumping, or lateral movement.
7. Final objective is achieved, such as long-term persistence or exfiltration.

## Impact

Success of this technique allows an attacker to bypass 32-bit environment restrictions, escalate privileges, and hide malicious activity within the context of legitimate Windows system processes. This can lead to full system compromise, exfiltration of sensitive organizational data, and long-term persistence within targeted enterprise endpoints.

## Recommendation

1. Deploy the Sigma rule below to identify cross-architecture execution patterns in endpoint telemetry.
2. Filter out known benign software updaters and legitimate compatibility tools within your environment to reduce noise.
3. Enable Sysmon Event ID 1 (Process Creation) or Windows Event Log 4688 to capture the required command-line and path telemetry.
4. Investigate any instances where the parent process in SysWOW64 is unsigned or anomalous.
