---
title: Detection of Registry Modifications to Block Executable Execution
slug: 2026-10-disallowrun-registry-modification
description: Attackers, including the Azorult malware group, modify the Windows 'DisallowRun' registry key to prevent security tools from executing, thereby facilitating evasion and persistence.
date: "2026-10-12T18:11:59Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - registry
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
    technique_id: T1112
    technique_name: Modify Registry
    evidence: This activity is significant as it can indicate an attempt to disable security tools, a tactic used by malware like Azorult.
    confidence_band: high
rules:
  - title: Detect Modification of DisallowRun Registry Key
    description: Detects modifications to the Windows registry DisallowRun key which can be used to prevent the execution of security tools.
    platform: sigma
    severity: medium
    tactics:
      - defense-evasion
    techniques:
      - T1112
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
    - action: Deploy Sigma rule to identify modifications to DisallowRun registry key.
      owner: Detection Engineering
      due: 48h
      evidence: Source provides specific registry path and value for detection.
  hunt_leads:
    - lead: Search for historical changes to the DisallowRun key on endpoint registry datamodel.
      technique_id: T1112
      data_needed:
        - Registry Event Data
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: The registry path is highly sensitive and rarely modified.
---

This threat brief focuses on the exploitation of the Windows registry to manipulate application execution policies. Specifically, the activity involves modifying the 'DisallowRun' registry key, located under 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\'. By setting this value to '0x00000001', an attacker can effectively blacklist specific executables, preventing them from starting.

This technique is a known tactic employed by various malware families, including Azorult, to neutralize defensive capabilities. By blocking the execution of security agents, endpoint protection platforms (EPP), or monitoring tools, an attacker can operate within the compromised host with significantly reduced risk of detection. Defenders must monitor registry modification events to identify unauthorized changes to this key, as it rarely requires modification by standard administrative tasks in a stable environment.

## Attack Chain

1. Attacker gains initial access to the Windows host through a spearphishing attachment or exploit.
2. Malware or a malicious script executes with elevated privileges to gain necessary registry access.
3. The attacker locates the registry path 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun'.
4. The attacker modifies the 'DisallowRun' value to '0x00000001' to activate application blocking.
5. The attacker defines specific subkeys or values under 'DisallowRun' corresponding to security tool process names (e.g., 'avp.exe', 'sysmon.exe').
6. The operating system prevents the targeted security applications from launching during subsequent user sessions or upon attempt.
7. The attacker proceeds with secondary payloads, data exfiltration, or lateral movement while defensive tools remain crippled.

## Impact

Successful exploitation allows an attacker to maintain persistent access and evade detection on the targeted system. By selectively blocking security-critical binaries, the attacker effectively blindfolds security operations teams. This technique has been observed in various campaigns, specifically attributed to the Azorult info-stealer, targeting a range of systems where the adversary aims to prevent security software interference.

## Recommendation

* Deploy the provided Sigma rule to monitor registry modifications in the 'DisallowRun' hive via Sysmon Event ID 13.
* Configure endpoint security agents to alert on any modification to the 'Policies\Explorer' registry subkeys.
* Establish a baseline for legitimate administrative applications that might manage these registry settings and exclude them from detection logic.
