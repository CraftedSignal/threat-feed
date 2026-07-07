---
title: AI Agents Mimic Adversarial Behavior, Triggering Security Detections
slug: 2026-07-ai-agent-detection-challenges
description: AI coding agents such as Claude Code, Cursor, Codex, and GStack are increasingly exhibiting behaviors on Windows endpoints that mimic adversarial tradecraft, including credential access, LOLBin usage for ingress, command-line obfuscation, and persistence mechanisms, thereby triggering existing security detection rules designed for malicious activity and posing significant false positive challenges for detection engineers.
date: "2026-07-07T17:43:32Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - ai
  - detection-engineering
  - false-positive
  - windows
  - behavioral-detection
vendors:
  - Anthropic
  - OpenAI
  - Microsoft
  - Python Software Foundation
products:
  - Claude Code
  - Cursor
  - Codex
  - GStack
  - Windows
  - PowerShell
  - cmdkey.exe
  - certutil.exe
  - bitsadmin.exe
  - Python
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
    evidence: The Creds_3b telemetry shows that this skill chain uses PowerShell to decrypt sensitive browser data.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
    evidence: 'The activity tree also shows a command spawned via Claude that dumps stored credentials from Windows Credential Manager: ''C:\Windows\system32\cmdkey.exe'' /list'
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: 'The PowerShell command line confirms what the rule detected: powershell -NoProfile -Command ''Add-Type -AssemblyName System.Security;...'''
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: 'The activity tree also shows a command spawned via Claude that dumps stored credentials from Windows Credential Manager: ''C:\Windows\system32\cmdkey.exe'' /list'
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1027
    technique_name: Obfuscated Files or Information
    evidence: AI agents are generating PowerShell with similar formatting patterns in their command lines.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: The silent distribution is more spread out, with evasion and C2 categories prominent. This reflects agents performing network calls...
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
    evidence: The silent distribution is more spread out, with evasion and C2 categories prominent. This reflects agents performing network calls...
    confidence_band: med
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
    evidence: The AI agent (OpenAI Codex) attempted to download and run a Python installer. It started with certutil.exe... then switched to bitsadmin.exe...
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: The example below shows Cursor using a PowerShell script to write a VBScript file into the Windows startup folder.
    confidence_band: high
references:
  - https://www.sophos.com/en-us/blog/2607_agents_vs_telemetry
iocs:
  - type: command-line
    value: powershell -NoProfile -Command "Add-Type -AssemblyName System.Security; $stdin = [Console]::In.ReadToEnd().Trim(); $bytes = [System.Convert]::FromBase64String($stdin); $dec = [System.Security.Cryptography.ProtectedData]::Unprotect($bytes, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser); Write-Output ([System.Convert]::ToBase64String($dec))"
  - type: command-line
    value: '"C:\Windows\system32\cmdkey.exe" /list'
  - type: command-line
    value: certutil.exe -urlcache -split -f https://www.python.org/.../python-3.14.6-amd64.exe
  - type: command-line
    value: bitsadmin.exe /transfer PythonDownload /download /priority normal (same URL)
  - type: url
    value: https://www.python.org/.../python-3.14.6-amd64.exe
  - type: domain
    value: python.org
  - type: command-line
    value: powershell.exe -ExecutionPolicy Bypass -File C:\Users\<username>\AppData\Local\Temp\ps-script-6a6de53c-7d17-4e73-9538-00a77b8b2a2d.ps1
  - type: file-path
    value: C:\Users\<username>\AppData\Local\Temp\ps-script-6a6de53c-7d17-4e73-9538-00a77b8b2a2d.ps1
  - type: file-path
    value: C:\Users\<username>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\Launch-EZConvert-ConsoleOnly.vbs
ioc_counts:
  command-line: 5
  domain: 1
  file-path: 2
  url: 1
---

Sophos X-Ops has analyzed how various AI coding agents, including Claude Code, Cursor, Codex, and those built on skill packs like GStack, are generating behavioral telemetry on Windows endpoints that strongly resembles adversarial tradecraft. These agents are designed to write code, install dependencies, automate browser tasks, and troubleshoot issues by attempting multiple approaches. While their activity is benign in context, it frequently triggers endpoint detection rules originally designed to catch malicious actions. This phenomenon creates significant detection engineering challenges, leading to high false positives and requiring security teams to re-evaluate and tune their existing behavioral protections to differentiate between legitimate AI agent operations and actual threats. This trend has been observed since June 2026, with widespread adoption of these agents across customer environments.

## Attack Chain

This brief details observed AI agent behaviors that mimic typical stages of an attack chain, rather than a malicious campaign.

1.  **AI Agent Execution:** An AI agent (e.g., Claude Code, Cursor) is launched, initiating automated tasks and spawning child processes for various coding and problem-solving activities.
2.  **Credential Access Attempts:** Agents attempt to access sensitive system components, such as browser credential stores using PowerShell to decrypt DPAPI-protected data, or Windows Credential Manager via `cmdkey.exe /list`.
3.  **Ingress Tool Transfer (LOLBins):** When external resources are required (e.g., downloading a Python installer), agents leverage living-off-the-land binaries (LOLBins) such as `certutil.exe -urlcache` or `bitsadmin.exe /transfer` for downloading.
4.  **Adaptive Tool Pivoting:** If an initial command fails (e.g., `certutil.exe` is blocked), the AI agent will pivot and attempt alternative tools or techniques (e.g., `bitsadmin.exe`), mirroring an adversary's resilience.
5.  **Defense Evasion (Obfuscation):** Agents generate command-line patterns, including PowerShell scripts with specific string-formatting techniques, that can appear obfuscated and trigger rules designed to detect malicious command-line obfuscation.
6.  **Persistence Mechanism Deployment:** For certain tasks, agents write files to persistence locations, such as a VBScript file into the Windows Startup folder, executed via PowerShell, mirroring adversary persistence techniques.
7.  **Network Activity and Child Processes:** Agents perform network calls and spawn various child processes that can resemble Command and Control (C2) activity and other execution tactics, contributing to broad detection rule hits.

## Impact

The primary impact of AI agent activities mimicking adversarial tradecraft is a significant increase in false positives for security detection systems. Rules that historically flagged malicious behavior are now triggered by benign automated tasks, leading to alert fatigue, increased analyst workload, and the risk of legitimate threats being overlooked amidst the noise. Organizations utilizing AI coding agents face the operational challenge of differentiating between productive AI-driven actions and genuine attack indicators, necessitating substantial effort in rule tuning and behavioral whitelisting, especially on Windows environments. This challenge impacts all sectors adopting AI development tools.

## Recommendation

*   Tune existing detection rules that flag credential access (e.g., `Creds_3b`-like rules for PowerShell using `System.Security.Cryptography.ProtectedData::Unprotect`) to account for expected AI agent activity.
*   Review and refine detection rules similar to `Exec_16a` that identify PowerShell command-line obfuscation, specifically adapting them to handle patterns commonly generated by AI agents.
*   Implement enhanced monitoring for `certutil.exe` and `bitsadmin.exe` usage, particularly when these LOLBins are initiated by processes associated with identified AI agents, to refine `Lateral_1b` and `Exec_5a`-like detection rules.
*   Investigate `Persist_2a`-like rule triggers that detect writes to Windows Startup folders, analyzing the invoking process and script contents for legitimate AI agent context.
*   Ensure comprehensive logging for PowerShell command execution, process creation, and network connections is enabled to provide necessary telemetry for distinguishing AI agent activity.
