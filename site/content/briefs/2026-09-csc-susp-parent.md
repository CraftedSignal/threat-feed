---
title: Suspicious Csc.exe Execution via Unconventional Parent Processes
slug: 2026-09-csc-susp-parent
description: Adversaries frequently leverage the C# compiler (csc.exe) to compile malicious code on-the-fly, often triggered by suspicious parent processes such as office applications or script engines.
date: "2026-09-03T14:36:33Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - living-off-the-land
  - execution
  - stealth
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1218.005
    technique_name: Mshta
    evidence: Adversaries leverage the C# compiler to compile malicious code on-the-fly.
    confidence_band: high
references:
  - https://www.uptycs.com/blog/warzonerat-can-now-evade-with-process-hollowing
  - https://reaqta.com/2017/11/short-journey-darkvnc/
  - https://www.pwc.com/gx/en/issues/cybersecurity/cyber-threat-intelligence/yellow-liderc-ships-its-scripts-delivers-imaploader-malware.html
rules:
  - title: Detect Suspicious Csc.exe Parent Processes
    description: Detects the execution of csc.exe by suspicious parent processes, including office applications and script engines, which may indicate malicious payload compilation.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1218.005
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
    - action: Deploy Sigma rule to detect suspicious csc.exe execution parents.
      owner: Detection Engineering
      due: 24h
  hunt_leads:
    - lead: Search for csc.exe process creation events with parents in %TEMP% or %APPDATA%.
      technique_id: T1218.005
      data_needed:
        - Process creation events
      priority: high
      confidence: high
      disposition: hunt_now
---

The C# compiler (csc.exe) is a legitimate Windows binary often abused by threat actors to perform just-in-time compilation of payloads. By invoking csc.exe via script engines (WScript, CScript, PowerShell) or office application macros, attackers can transform obfuscated source code or embedded strings into executable binaries directly in memory or within temporary directories. This technique, commonly referred to as "living off the land" (LotL), allows for effective evasion of static file-based signature detection, as the malicious executable is generated on the target endpoint at runtime. Defenders should focus on identifying atypical parent-child process relationships involving csc.exe, particularly when the parent is an application not typically associated with development or build tasks.

## Attack Chain

1. Initial delivery via spearphishing attachment (e.g., weaponized Office document or script).
2. Execution of malicious macros or script code embedded in the delivery file.
3. The parent process (e.g., winword.exe, outlook.exe, powershell.exe) creates a child process: csc.exe.
4. The parent process provides command-line arguments to csc.exe containing the source code path or parameters for compilation.
5. csc.exe compiles the provided source code into a temporary or hidden executable file.
6. The newly compiled binary is executed to establish persistence or inject malicious code into other processes (e.g., process hollowing).
7. Final objective achieved (e.g., deployment of RAT, infostealer, or ransomware).

## Impact

Successful exploitation allows threat actors to bypass static security controls and execute arbitrary code in memory. This technique has been observed in various malware campaigns, including WarzoneRAT and Yellow Liderc, resulting in data exfiltration, persistent unauthorized access, and potential ransomware deployment.

## Recommendation

- Deploy the provided Sigma rule to monitor for suspicious process-creation events where csc.exe is spawned by unconventional parents.
- Establish a baseline for legitimate csc.exe execution patterns in the environment, specifically for DevOps or build servers, and filter these from the detection.
- Enable Sysmon or Windows Event Log (Event ID 4688) with command-line auditing to capture the full invocation of csc.exe for incident investigation.
- Investigate any occurrences of csc.exe spawning from paths such as \Temp\, \Public\, or \AppData\ directories, as these are highly indicative of malicious activity.
