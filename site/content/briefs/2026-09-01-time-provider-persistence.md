---
title: Abuse of Windows Time Service for Persistence via TimeProvider Registry
slug: 2026-09-01-time-provider-persistence
description: Adversaries may achieve persistence by registering a malicious DLL within the Windows Time service (W32Time) configuration, allowing for arbitrary code execution upon system boot.
date: "2026-09-01T13:09:17Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - persistence
  - windows
  - registry
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: Adversaries may abuse time providers to execute DLLs when the system boots.
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_timeproviders_dllname.yml
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1547.003/T1547.003.md
rules:
  - title: Detect New TimeProviders Registered With Uncommon DLL Name
    description: Detects processes setting a new DLL in DllName under HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W32Time\TimeProvider to achieve persistence.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege-escalation
    techniques:
      - T1547.003
    data_sources:
      - registry_set
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Deploy Sigma detection rule to monitor W32Time registry hive
      owner: Detection Engineering
      due: 48h
      evidence: Sigma rule provided in brief
  hunt_leads:
    - lead: Audit current HKLM\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders configuration for non-standard DLL paths.
      technique_id: T1547.003
      data_needed:
        - Registry configuration export
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Persistence mechanism targets W32Time registry subkeys
---

Adversaries targeting Windows environments can achieve persistence and potential privilege escalation by manipulating the Windows Time service (W32Time) configuration. The W32Time service, responsible for network time synchronization, supports custom time providers defined in the registry under HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders. By adding a new subkey to this location and defining a custom 'DllName' value pointing to a malicious library, an attacker ensures the execution of their code when the system starts or the W32Time service initializes. This technique is particularly effective as it operates within a trusted system service and is often overlooked by standard startup folder or Run-key monitoring. Defenders should monitor registry modifications targeting the W32Time registry hive to identify unauthorized provider registrations.

## Attack Chain

1. Attacker gains administrative access to the target host.
2. Attacker prepares a malicious DLL designed to execute a payload or beacon.
3. Attacker drops the malicious DLL into a system-accessible directory, typically within System32.
4. Attacker modifies the registry key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders to create a new subkey.
5. Attacker sets the 'DllName' value for the new subkey to the path of the malicious DLL.
6. Attacker configures the 'Enabled' value for the new subkey to '1' to activate the provider.
7. W32Time service loads the specified DLL during the next service startup or system boot.
8. Malicious code executes in the context of the service, achieving persistence and potential escalation.

## Impact

Successful exploitation results in persistent, high-privilege code execution upon system boot. This allows attackers to maintain long-term access, bypass standard user-level security controls, and potentially facilitate lateral movement or data exfiltration from within a trusted system process.

## Recommendation

Deploy the provided Sigma rule to monitor for registry modifications within the W32Time TimeProviders hive that reference non-standard DLL paths. Enable Windows registry auditing on the specific key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders to capture all 'SetValue' and 'CreateKey' events.
