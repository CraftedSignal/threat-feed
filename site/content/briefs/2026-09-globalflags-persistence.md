---
title: Windows Persistence via GlobalFlags and SilentProcessExit Registry Keys
slug: 2026-09-globalflags-persistence
description: Adversaries abuse the Image File Execution Options (IFEO) registry keys to establish persistence or intercept process termination by configuring GlobalFlags and SilentProcessExit mechanisms.
date: "2026-09-01T13:10:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - persistence
  - privilege-escalation
  - registry
  - windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1546
    technique_name: Event Triggered Execution
    evidence: Detects registry persistence technique using the GlobalFlags and SilentProcessExit keys
    confidence_band: high
references:
  - https://oddvar.moe/2018/04/10/persistence-using-globalflags-in-image-file-execution-options-hidden-from-autoruns-exe/
  - https://www.deepinstinct.com/2021/02/16/lsass-memory-dumps-are-stealthier-than-ever-before-part-2/
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_persistence_globalflags.yml
rules:
  - title: Detect Potential Persistence Via GlobalFlags or SilentProcessExit
    description: Detects registry modifications to GlobalFlags or SilentProcessExit keys under Image File Execution Options which can be used for process monitoring or persistence.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege-escalation
    techniques:
      - T1546.012
    data_sources:
      - registry_set
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy registry monitoring rules for IFEO keys
      owner: Detection Engineering
      due: 48h
      evidence: Source provides logic for detecting IFEO manipulation
  hunt_leads:
    - lead: Search for existing IFEO entries that point to non-standard or hidden executables
      technique_id: T1546.012
      data_needed:
        - Registry hive data for HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: This technique is known to be used for stealthy persistence
---

This threat involves the exploitation of the Image File Execution Options (IFEO) registry configuration to gain persistence or facilitate stealthy process monitoring. By modifying the GlobalFlags value within an IFEO key, attackers can force a process to execute an arbitrary monitoring tool whenever it exits. This is frequently coupled with the SilentProcessExit registry key, which allows for advanced control over process termination behavior, such as launching a monitor process or capturing memory dumps. This technique is particularly dangerous because it can be used to achieve privilege escalation or hide malicious activity by hooking into legitimate system binaries, often bypassing standard autorun detection tools. Defenders should monitor registry modifications targeting these specific keys under the Windows NT CurrentVersion configuration tree.

## Attack Chain

1. The attacker gains elevated administrative access to the target host.
2. The attacker identifies a target process frequently executed by the system or a user (e.g., explorer.exe).
3. The attacker creates or modifies the registry key HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\[TargetProcess].
4. The attacker sets the GlobalFlag registry value to enable reporting or process monitoring (e.g., FLG_ENABLE_KDEBUG_SYMBOL_LOAD).
5. The attacker configures the SilentProcessExit key for the target process, specifying a malicious path in the MonitorProcess value.
6. The attacker configures the ReportingMode to ensure the monitor process is invoked upon the target process exit.
7. When the target process exits, the operating system automatically launches the binary specified in the MonitorProcess value with elevated privileges.
8. The monitor process executes arbitrary code, establishing persistent access or performing data exfiltration.

## Impact

Successful exploitation allows for stealthy, high-privilege persistence that remains hidden from many standard persistence scanners. This mechanism can be used to gain unauthorized code execution every time a system process terminates or is restarted, potentially facilitating long-term access, lateral movement, and the silent collection of sensitive information or memory dumps from privileged processes like lsass.exe.

## Recommendation

Deploy the provided Sigma rules to monitor for unauthorized modifications to the Windows registry. Prioritize alerts triggered by modifications to the Image File Execution Options and SilentProcessExit keys, as these are rarely changed by legitimate administrative activity in a steady-state environment.

- Enable Sysmon or Windows Registry auditing to capture Event ID 12 (Registry Create) and 13 (Registry Set Value).
- Use the provided Sigma rules to alert on modifications to the specific registry paths identified.
- Baseline existing IFEO configurations in your environment to distinguish between authorized debugging tools and malicious entries.
