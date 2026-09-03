---
title: PowerShell Download and Execution Cradles
slug: 2026-09-powershell-cradles
description: This brief documents common PowerShell patterns used by threat actors, including FIN7, to download and execute arbitrary payloads directly into memory using download cradles.
date: "2026-09-03T12:40:30Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - FIN7
  - Carbon Spider
  - Sangria Tempest
tags:
  - fileless-malware
  - powershell
  - execution
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The rule detects PowerShell download and execution cradles, which are techniques used to execute code via the command interpreter.
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_powershell_download_iex.yml
  - https://labs.withsecure.com/publications/fin7-target-veeam-servers
rules:
  - title: Detect PowerShell Download and Execution Cradles
    description: Detects the use of PowerShell cmdlets to download remote content combined with execution via Invoke-Expression.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy the Sigma rule to detect PowerShell download and execution cradles.
      owner: Detection Engineering
      due: 48h
      evidence: Source provides rule logic for identifying download and execution patterns.
  hunt_leads:
    - lead: Search for process creation events where PowerShell command lines include both download cmdlets and 'IEX'.
      technique_id: T1059.001
      data_needed:
        - CommandLine
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: This pattern is highly indicative of suspicious activity.
---

Threat actors, including groups like FIN7, frequently employ PowerShell download cradles to facilitate the delivery and execution of malicious code in memory. These techniques bypass traditional file-based antivirus solutions by fetching remote content - often second-stage backdoors or beacons - and piping it directly into the Invoke-Expression (IEX) cmdlet. These commands are often obfuscated to hinder signature-based detection. This method is a hallmark of initial access and secondary infection stages across various targeted campaigns, particularly against high-value infrastructure like Veeam backup servers. Defenders must monitor process command lines for the combination of download cmdlets and execution primitives to identify these potentially malicious memory-only execution chains.

## Attack Chain

1. Attacker gains initial access or escalation, dropping a short PowerShell stubs.
2. The stubs use cmdlets such as 'Invoke-WebRequest' or 'irm' to initiate a web request.
3. The request targets an attacker-controlled URI to download a remote payload.
4. The downloaded string or file content is passed via the pipeline to 'IEX' or 'Invoke-Expression'.
5. The 'IEX' alias (including obfuscated variations like 'I`E`X') executes the payload content in memory.
6. The payload, often an obfuscated script, initiates a C2 connection or performs credential harvesting.
7. Final objective (exfiltration, ransomware deployment, or secondary persistence) is achieved in the context of the running PowerShell process.

## Impact

Successful execution of these cradles allows for fileless malware deployment, enabling attackers to maintain persistence, escalate privileges, and exfiltrate data while minimizing their footprint on the target disk. Observed targets include enterprise infrastructure and backup systems.

## Recommendation

1. Deploy the Sigma rule below to detect the concatenation of download cmdlets and execution primitives.
2. Baseline your environment for legitimate PowerShell installers that may use similar syntax and add them to a strict allowlist.
3. Enable Enhanced PowerShell Logging (Script Block Logging) to capture the de-obfuscated content of these execution cradles.
4. Monitor for PowerShell instances originating from non-administrative contexts or uncommon parent processes.
