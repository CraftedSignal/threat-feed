---
title: Detection of .NET Proxy Execution via Script-Based Launchers
slug: 2026-10-net-proxy-execution
description: Adversaries are leveraging trusted .NET utilities spawned by scripts in user-writable directories to execute code and maintain persistence, a technique observed in recent VIP Keylogger campaigns.
date: "2026-10-09T12:19:23Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - execution
  - windows
  - malware
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: Signed Binary Proxy Execution
    evidence: That pattern is consistent with adversaries using trusted .NET binaries as a proxy to run code while hiding execution behind script parents.
    confidence_band: high
rules:
  - title: Detect Proxy Execution of .NET Utilities via Scripts
    description: Detects .NET binaries spawned by script interpreters from suspicious user-writable locations.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1218
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
    - action: Deploy the Sigma detection rule to identify .NET utility proxy execution.
      owner: Detection Engineering
      due: 24h
      evidence: Source analytic identifies this as a critical detection pattern.
  hunt_leads:
    - lead: Search for script interpreters (powershell.exe, cmd.exe) executing binaries from \Temp\ or \AppData\ paths.
      technique_id: T1218
      data_needed:
        - Process creation logs with parent and image paths
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Analytic identifies these paths as high-risk for proxy execution.
  mitigation_plan:
    - priority: medium_term
      action: Implement AppLocker or WDAC policies to restrict execution from user-writable directories.
      owner: IT Operations
      addresses: Technique T1218
      evidence: Hardening reduces the viability of script-based proxy execution.
---

Security research has identified a persistent technique utilized by the VIP Keylogger malware family to achieve defense evasion and code execution. Attackers utilize legitimate, signed .NET framework utilities - specifically aspnet_compiler.exe, msbuild.exe, regasm.exe, InstallUtil.exe, and vbc.exe - as proxies to run malicious code. The execution is typically initiated by script-based parents, such as batch files, PowerShell, or VBScript, originating from low-trust or user-writable directories including Temp, AppData, or the Recycle Bin. 

This approach masks the execution of malicious payloads by wrapping them in trusted binary processes, effectively bypassing simple signature-based detection. Defenders should focus on monitoring parent-child process relationships where these specific .NET binaries are launched by script interpreters from suspicious file system paths. This behavior is highly anomalous in production environments and warrants immediate investigation when detected.

## Attack Chain

1. Attacker drops a malicious script (e.g., .bat, .vbs, .ps1) into a user-writable directory such as %TEMP% or C:\Users\Public\.
2. The malicious script is executed by the user or through an initial access trigger (e.g., phishing attachment, drive-by download).
3. The script launches a legitimate .NET utility (e.g., msbuild.exe or regasm.exe) to avoid detection by security software.
4. The .NET utility is instructed via command-line arguments or configuration files to execute secondary code or malicious DLLs.
5. The parent script process terminates or remains resident to continue the execution flow.
6. The .NET utility performs the intended malicious objective, such as credential theft or establishing C2 communication.
7. Data exfiltration or secondary payload staging is executed under the context of the trusted Microsoft-signed binary.

## Impact

Successful exploitation allows for stealthy code execution on Windows endpoints, enabling malware like the VIP Keylogger to operate undetected. This can lead to full system compromise, exfiltration of sensitive user data, and persistence establishment within the enterprise environment.

## Recommendation

1. Deploy the provided Sigma rule to identify anomalous parent-child process relationships between script interpreters and .NET utilities.
2. Configure EDR telemetry to capture full command-line arguments and process GUIDs for all child processes spawned by script interpreters.
3. Restrict execution permissions for scripts and non-administrative binaries within high-risk directories such as \Temp\, \Public\, and \AppData\Local\Temp\.
4. Perform periodic threat hunting for parent-child pairings of scripting engines spawning binaries listed in the detection rule.
