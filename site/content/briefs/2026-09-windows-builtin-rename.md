---
title: Detection of Renaming Windows Built-in Accounts
slug: 2026-09-windows-builtin-rename
description: Adversaries rename high-privileged Windows built-in accounts to evade security monitoring while maintaining access associated with reserved RIDs 500-504.
date: "2026-09-06T22:41:29Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:microsoft:configuration_manager_2503:-:*:*:*:*:*:*:*
  - cpe:2.3:a:microsoft:configuration_manager_2509:-:*:*:*:*:*:*:*
  - cpe:2.3:a:microsoft:configuration_manager_2603:-:*:*:*:*:*:*:*
tags:
  - windows
  - persistence
  - defense-evasion
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: Attackers commonly rename the built-in Administrator account to evade detections that alert on the literal account name, while retaining the full privileges of the RID-500 account.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
    evidence: Renaming Guest, krbtgt, or other reserved accounts is highly unusual in any legitimate environment.
    confidence_band: high
cves:
  - id: CVE-2026-47301
    cvss: 8.8
    epss: 0.00964
references:
  - https://attack.mitre.org/techniques/T1078/003/
  - https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4781
  - https://nvd.nist.gov/vuln/detail/cve-2026-47301
rules:
  - title: Detect Renaming of Windows Built-in Accounts
    description: Detects renaming of Windows built-in accounts (Administrator, Guest, etc.) with reserved RIDs 500-504 by monitoring Event ID 4781.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1078.003
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
    - action: Deploy Sigma rule to monitor for Event ID 4781 involving sensitive RIDs.
      owner: Detection Engineering
      due: 24h
      evidence: Source analytic defines this as a high-fidelity detection technique.
  mitigation_plan:
    - priority: medium_term
      action: Review all account renaming activities and enforce strict change control for sensitive system accounts.
      owner: IT Operations
      addresses: T1078.003
      evidence: Source identifies hardening as a legitimate but uncommon cause for this activity.
---

Attackers often rename Windows built-in accounts, such as Administrator, Guest, or krbtgt, to evade detection mechanisms that specifically alert on these well-known account names. By changing the account name while retaining the underlying Security Identifier (SID) associated with reserved RIDs (500-504), an attacker can maintain full system privileges and persistence while blending in with legitimate user account naming conventions. This behavior is highly irregular in standard production environments and is often indicative of malicious activity, including persistence establishment, privilege escalation, or attempts to bypass security-information-and-event-management (SIEM) alerts that flag specific, hardcoded account names. Defenders must monitor Windows Security Event ID 4781 to detect these unauthorized modifications, which may also be associated with broader exploitation efforts such as CVE-2026-47301.

## Attack Chain

1. Attacker gains administrative access to a Windows host.
2. Attacker enumerates built-in accounts to identify the RID-500 Administrator or other high-privileged targets.
3. Attacker uses the net user command or administrative interfaces to rename the account.
4. The operating system generates Event ID 4781 to record the account name change.
5. Attacker proceeds to perform post-exploitation tasks, such as credential dumping or lateral movement, under the renamed account context.
6. Attacker leverages the modified account to maintain persistent access that evades static account-name-based detection rules.

## Impact

Renaming built-in accounts allows attackers to persist undetected in an environment with elevated privileges. This technique can lead to complete host compromise, unauthorized access to sensitive data, and the ability to conduct further malicious actions across the network while circumventing traditional monitoring that triggers on standard names like 'Administrator'.

## Recommendation

- Deploy the provided Sigma rule to monitor Windows Security logs for Event ID 4781.
- Implement a process to validate any renaming of built-in accounts against authorized change control windows.
- Investigate any Event ID 4781 that involves accounts with SIDs ending in -500, -501, -502, -503, or -504.
- Patch systems against CVE-2026-47301 if relevant to the environment, as this technique is frequently observed in post-exploitation scenarios following broader system compromise.
