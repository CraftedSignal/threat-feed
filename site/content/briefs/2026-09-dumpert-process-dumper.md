---
title: Dumpert Process Memory Dumping Tool Activity
slug: 2026-09-dumpert-process-dumper
description: Detection of the Dumpert hacktool, used to dump memory from the lsass.exe process to facilitate credential theft.
date: "2026-09-24T11:12:39Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - credential-access
  - windows
  - hacktool
rules:
  - title: Detect Dumpert HackTool Execution
    description: Detects the use of Dumpert process dumper, which dumps the lsass.exe process memory
    platform: sigma
    severity: critical
    tactics:
      - credential-access
    techniques:
      - T1003.001
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
    - action: Deploy provided Sigma rule to SIEM environment.
      owner: Detection Engineering
      due: 24h
      evidence: Required for detecting credential dumping activity.
  hunt_leads:
    - lead: Search for process creation events involving unknown binaries interacting with lsass.exe.
      technique_id: T1003.001
      data_needed:
        - Sysmon Event ID 1
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Tool is known for targeting lsass.exe.
  mitigation_plan:
    - priority: immediate
      action: Implement endpoint restriction policies preventing unsigned code execution.
      owner: IT Operations
      addresses: Dumpert usage
      evidence: Reduces likelihood of unauthorized tool execution.
---

Dumpert is a Windows-based hacktool designed to perform memory dumping of the Local Security Authority Subsystem Service (lsass.exe). By extracting memory from this process, attackers aim to harvest sensitive credentials, including NTLM hashes and plaintext passwords, which are essential for lateral movement and privilege escalation within a Windows environment. The tool is known for implementing custom techniques to evade standard detection methods used by security software that monitors direct calls to memory dumping APIs. Monitoring for the execution of Dumpert is critical, as it signifies an active attempt by an adversary to perform credential access at the endpoint level, typically during the post-exploitation phase of an intrusion.

## Attack Chain

1. Attacker gains initial access to the target Windows system.
2. Attacker performs local enumeration to identify the process ID of lsass.exe.
3. Attacker drops the Dumpert executable or DLL onto the target file system.
4. Attacker executes Dumpert.exe or invokes Dumpert.dll via command line.
5. The tool utilizes direct system calls or custom API implementations to bypass common EDR hooks.
6. The memory contents of lsass.exe are read and written to a local dump file on disk.
7. The attacker exfiltrates the resulting memory dump file to an external command-and-control server.
8. Credentials are extracted offline using tools like Mimikatz to escalate privileges or move laterally.

## Impact

Successful execution of Dumpert provides adversaries with high-value credentials, enabling full account compromise, domain escalation, and long-term persistent access to the network. This activity is a precursor to large-scale data exfiltration and potential ransomware deployment.

## Recommendation

* Deploy the provided Sigma rule to detect the execution of the Dumpert binary or the loading of its associated DLL.
* Enable Sysmon process-creation logging (Event ID 1) to capture command line arguments and file hashes required for rule execution.
* Implement strict endpoint controls to restrict the execution of unauthorized binaries in temporary directories where such tools are commonly staged.
* Monitor for unexpected access to lsass.exe memory space by non-system processes.
