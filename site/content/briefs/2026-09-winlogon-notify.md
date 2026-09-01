---
title: Abuse of Winlogon Notify Registry Keys for Persistence
slug: 2026-09-winlogon-notify
description: Adversaries can achieve persistence and privilege escalation by modifying the Winlogon Notify registry key to trigger the execution of arbitrary DLLs during user login.
date: "2026-09-01T12:16:26Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - persistence
  - privilege-escalation
  - registry
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: Adversaries may abuse features of Winlogon to execute DLLs and/or executables when a user logs in.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: Winlogon.exe is a Windows component responsible for actions at logon/logoff as well as the secure attention sequence (SAS) triggered by Ctrl-Alt-Delete.
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_winlogon_notify_key.yml
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1547.004/T1547.004.md
rules:
  - title: Detect Winlogon Notify Key Modification
    description: Detects registry modifications to the Winlogon Notify key, which is used to trigger DLL execution at user logon
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege-escalation
    techniques:
      - T1547.004
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
    - action: Deploy the provided Sigma rule for Winlogon Notify modification detection
      owner: Detection Engineering
      due: 48h
      evidence: Rule defined in brief
  hunt_leads:
    - lead: Search for existing entries under the Winlogon\Notify registry hive pointing to files in user-writable directories
      technique_id: T1547.004
      data_needed:
        - Registry baseline export
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Registry structure is common persistence location
---

Adversaries may abuse the Winlogon Notify feature in Windows to maintain persistence and potentially elevate privileges. Winlogon.exe is a core Windows component responsible for handling user logon and logoff sequences, as well as the Secure Attention Sequence (SAS) triggered by the Ctrl-Alt-Delete key combination. By registering a malicious DLL under the HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify registry path, an attacker ensures that their code is loaded and executed by the Winlogon process whenever a user logs in. This technique is a well-documented method for achieving persistent execution that is transparent to the user and resilient across reboots. Defenders should monitor for unexpected registry modifications within the Notify subtree that point to suspicious or non-standard DLL locations.

## Impact

Successful exploitation of this technique allows an attacker to maintain a persistent foothold on an affected system with the privileges of the Winlogon process (SYSTEM), potentially leading to complete system compromise, credential theft, or the deployment of secondary payloads in the context of every user session.

## Recommendation

Detection engineering teams should monitor registry modifications targeting the Winlogon Notify keys to detect unauthorized persistence mechanisms. 
- Deploy the provided Sigma rule to detect registry set events targeting the Winlogon\Notify subkeys.
- Baseline existing legitimate DLL entries in the Winlogon Notify registry hive to reduce false positives during initial implementation.
- Implement monitoring for unsigned or suspicious DLLs residing in non-standard system directories that appear in the Winlogon registry configurations.
