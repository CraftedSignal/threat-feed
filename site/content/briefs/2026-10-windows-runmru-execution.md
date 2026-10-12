---
title: Detection of Indirect Command Execution via Windows RunMRU Registry Keys
slug: 2026-10-windows-runmru-execution
description: Adversaries, including those deploying Lumma Stealer via fake CAPTCHA campaigns, utilize the Windows RunMRU registry key to execute malicious commands while masking activity as legitimate user behavior.
date: "2026-10-12T18:20:53Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - defense-evasion
  - execution
  - registry
  - windows
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1202
    technique_name: Indirect Command Execution
    evidence: The following analytic detects modifications to the Windows RunMRU registry key, which stores a history of commands executed through the Run dialog box.
    confidence_band: high
rules:
  - title: Detect Suspicious RunMRU Command Execution
    description: Detects modifications to the Windows RunMRU registry key, which logs commands executed via the Run dialog. This is often used by malware to masquerade as legitimate user activity.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1202
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
    - action: Deploy the Sigma rule to monitor for RunMRU modifications.
      owner: Detection Engineering
      due: 48h
      evidence: Source Splunk ESQU detection content.
  hunt_leads:
    - lead: Search for historical registry modifications to RunMRU entries followed by process execution of cmd.exe or powershell.exe.
      technique_id: T1202
      data_needed:
        - Registry SET events
        - Process creation events
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Source links RunMRU modification to malicious command execution.
---

The Windows RunMRU registry key serves as a historical repository for commands executed through the 'Run' dialog box (Windows+R). This mechanism is frequently abused by threat actors, notably in recent campaigns involving Lumma Stealer and fake CAPTCHA delivery vectors, to achieve indirect command execution. By leveraging the Run dialog, attackers attempt to blend in with legitimate user activity, potentially bypassing traditional process-creation monitoring that focuses on common execution patterns. 

Defenders must monitor registry write events targeting the RunMRU path to identify anomalous command execution patterns. This technique, classified under indirect command execution, allows actors to achieve defense evasion or establish persistence by leveraging built-in Windows features that remain under-monitored in many environments. This detection methodology requires endpoint telemetry capturing detailed registry modifications, specifically focusing on command values rather than the system-managed MRUList index.

## Attack Chain

1. Attacker lures a victim via a fake CAPTCHA campaign on compromised websites.
2. Victim is prompted to download and execute a malicious payload.
3. The malware executes, often using obfuscated scripts or droppers.
4. The malware interacts with the Windows Registry to inject a command string into the 'RunMRU' key.
5. The Windows shell processes the command stored within the registry key.
6. The target command (e.g., PowerShell, cmd.exe) executes under the context of the current user.
7. The attacker maintains persistence or performs further exfiltration of credentials.

## Impact

Successful exploitation of this technique facilitates stealthy command execution, allowing adversaries to maintain a foothold on target systems and exfiltrate sensitive data. Observed in the context of infostealers like Lumma, this technique directly contributes to the compromise of user credentials, system configuration, and private user data. If left undetected, attackers can persistently execute arbitrary code under the guise of standard user interactions.

## Recommendation

* Deploy the Sigma rule below to monitor registry activity targeting the RunMRU key.
* Enable Sysmon Event ID 13 (RegistryValue-Set) to capture all modifications to the RunMRU registry hive.
* Tune the detection by creating an allowlist for known, legitimate maintenance or software update processes that interact with the Windows Explorer registry keys.
* Investigate endpoints where registry modification events show command strings associated with non-standard tools or obfuscated arguments.
