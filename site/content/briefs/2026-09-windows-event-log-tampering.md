---
title: Windows Event Log Access Tampering Via Registry
slug: 2026-09-windows-event-log-tampering
description: Attackers may modify registry-based Security Descriptor Definition Language (SDDL) strings for Windows Event Log channels to impair defensive monitoring by restricting access to log data.
date: "2026-09-01T12:09:48Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - defense-evasion
  - persistence
  - windows
  - registry
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: Modifications to these values can restrict access to specific users or groups, potentially aiding in defense evasion.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1112
    technique_name: Modify Registry
    evidence: Detects changes to the Windows EventLog channel permission values.
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_disable_windows_event_log_access.yml
  - https://www.atomicredteam.io/atomic-red-team/atomics/T1562.002#atomic-test-8---modify-event-log-channel-access-permissions-via-registry---powershell
  - https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language
rules:
  - title: Detect Windows Event Log Access Tampering Via Registry
    description: Detects unauthorized modifications to Windows Event Log channel registry keys that alter SDDL permissions to restrict log access.
    platform: sigma
    severity: high
    tactics:
      - defense-impairment
      - persistence
      - privilege-escalation
    techniques:
      - T1112
      - T1562.002
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
    - action: Deploy the registry monitoring rule to detect Event Log SDDL modifications.
      owner: Detection Engineering
      due: 48h
      evidence: Source provides explicit paths for monitoring Event Log channel access.
  mitigation_plan:
    - priority: medium_term
      action: Enforce strict registry access controls to prevent non-administrative processes from modifying event log configuration keys.
      owner: IT Operations
      addresses: T1562.002
      evidence: Registry configuration is the primary vector for this defense impairment.
---

Adversaries utilize registry modification techniques to impair security monitoring on Windows systems by altering the access permissions of specific Event Log channels. By modifying the Security Descriptor Definition Language (SDDL) strings associated with keys such as 'CustomSD' or 'ChannelAccess', attackers can effectively deny read or write access to authorized accounts or automated security tools. This defense impairment technique prevents security operations teams from viewing event logs via standard utilities like Event Viewer, wevtutil, or PowerShell's Get-EventLog cmdlet. This activity is often associated with post-exploitation phases where attackers aim to maintain persistence or cover their tracks by preventing the recording or auditing of malicious actions. Defenders should monitor registry modifications targeting Event Log configuration paths for unauthorized SDDL string changes.

## Attack Chain

1. Attacker gains administrative access to the target Windows system.
2. Attacker identifies Event Log registry configurations under HKLM\SYSTEM\CurrentControlSet\Services\EventLog\ or HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels.
3. Attacker uses reg.exe or PowerShell to set the 'CustomSD' or 'ChannelAccess' registry values.
4. Attacker inserts a "Deny" access control entry into the SDDL string (e.g., D:(D;;0x1;;;WD)).
5. The registry change propagates, updating the security descriptor for the target log channel.
6. Legitimate users or automated monitoring services are denied access to the log channel.
7. Attacker executes further malicious activity, which remains hidden or inaccessible to defensive review.

## Impact

Successful manipulation of Event Log access permissions directly degrades the visibility of the security operations team. This facilitates defense evasion, allowing attackers to perform subsequent malicious operations, such as lateral movement or data exfiltration, without leaving an audit trail that can be consumed by SIEM or EDR platforms.

## Recommendation

1. Deploy the provided Sigma rule to detect modifications to Event Log registry keys.
2. Monitor registry modification events targeting 'CustomSD' or 'ChannelAccess' specifically for strings containing 'D:(D;'.
3. Validate detection logic using the referenced Atomic Red Team tests for T1562.002.
4. Ensure that system-level updates initiated by 'TrustedInstaller.exe' are correctly filtered to avoid false positives.
