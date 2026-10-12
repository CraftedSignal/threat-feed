---
title: Detection of Windows Registry Modification for LongPathsEnabled
slug: 2026-10-long-paths-enabled
description: Adversaries, including the BlackByte ransomware group, modify the 'LongPathsEnabled' registry key to bypass Windows 260-character file path limitations, enabling the concealment and execution of malicious payloads.
date: "2026-10-12T18:12:37Z"
type: threat
types:
  - threat
severities:
  - medium
actors:
  - BlackByte
tags:
  - defense-evasion
  - registry-modification
  - persistence
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
    evidence: Adversaries, including malware like BlackByte, exploit this setting to bypass file path limitations, potentially aiding in evasion techniques.
    confidence_band: high
rules:
  - title: Detect Modification of LongPathsEnabled Registry Key
    description: Detects an attempt to enable the LongPathsEnabled registry key, which may be used by adversaries to hide malicious files in long directory paths.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
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
    - action: Deploy Sigma detection rule to SIEM
      owner: Detection Engineering
      due: 48h
      evidence: Source provides analytic rule logic for registry modifications.
  hunt_leads:
    - lead: Search for historical changes to the LongPathsEnabled key in existing registry logs
      technique_id: T1112
      data_needed:
        - Registry log data (Sysmon ID 13 or Windows Security Event ID 4657)
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Registry modification is a known TTP used by BlackByte.
  mitigation_plan:
    - priority: medium
      action: Review group policy to restrict manual registry modifications by non-privileged accounts
      owner: IT Operations
      addresses: T1112
      evidence: Defense evasion via registry modification.
---

The Windows registry setting "LongPathsEnabled," located under the "FileSystem" control key, allows the operating system to support file paths exceeding the traditional 260-character limit (MAX_PATH). While this feature is designed for administrative convenience, threat actors frequently target this setting to facilitate evasion. By enabling this configuration, attackers can store malicious binaries, obfuscated scripts, or exfiltrated data in deep directory structures that are difficult for standard security tools and administrative utilities to access or inspect. 

Observed activity from groups such as BlackByte indicates that adversaries modify this key as part of their post-exploitation and persistence strategy. Monitoring for unauthorized changes to this registry hive provides an opportunity for defenders to intercept a critical stage of an attacker's evasion and concealment process before they execute final-stage payloads.

## Attack Chain

1. Initial access is established on the target Windows system via phishing or exploitation.
2. The attacker gains administrative or SYSTEM-level privileges required to modify system-wide registry hives.
3. The attacker locates the registry key at HKLM\SYSTEM\CurrentControlSet\Control\FileSystem\LongPathsEnabled.
4. The attacker executes a command (e.g., reg add) to set the value of LongPathsEnabled to 1.
5. The attacker creates a deeply nested directory structure exceeding 260 characters in length.
6. The attacker drops and executes malicious payloads within these nested directories to evade security scanning.
7. The objective is achieved, such as long-term persistence or data exfiltration.

## Impact

Successful exploitation of this registry setting allows attackers to bypass security visibility by concealing malicious files in directory paths that standard tools cannot process. This increases the likelihood of long-term persistence and the successful execution of ransomware or other malicious payloads within an environment, potentially leading to total system compromise and data loss.

## Recommendation

* Deploy the provided Sigma rule to detect any process modifying the "LongPathsEnabled" registry value.
* Establish a baseline of authorized administrative activity to reduce noise, as legitimate configuration management systems may occasionally toggle this setting.
* Enable Sysmon Event ID 13 (RegistryEvent) across all endpoints to ensure registry modifications are logged with sufficient process context.
* Audit existing systems for the current state of the LongPathsEnabled key to identify unauthorized changes that may have occurred prior to rule implementation.
