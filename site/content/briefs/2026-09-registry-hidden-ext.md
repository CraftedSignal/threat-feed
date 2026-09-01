---
title: Registry Modification to Conceal File Extensions
slug: 2026-09-registry-hidden-ext
description: Adversaries modify Windows registry keys to hide file extensions and system files, facilitating the masquerading of malicious executables.
date: "2026-09-01T12:11:36Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - windows
  - registry
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1112
    technique_name: Modify Registry
    evidence: The technique involves modifying the registry to change File Explorer behavior.
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_hidden_extention.yml
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1112/T1112.md#atomic-test-1---modify-registry-of-current-user-profile---cmd
  - https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?name=TrojanSpy%3aMSIL%2fHakey.A
rules:
  - title: Detect Registry Modification to Hide File Extensions
    description: Detects modifications to Windows registry keys that hide file extensions or system files, often used to masquerade malicious executables.
    platform: sigma
    severity: medium
    tactics:
      - persistence
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
      evidence: Rule provided in source.
  hunt_leads:
    - lead: Search historical registry logs for the specified keys to identify past masquerading attempts.
      technique_id: T1112
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Source documentation of malicious registry use.
---

Threat actors frequently modify specific Windows registry keys to alter File Explorer behavior, specifically to hide known file extensions and system-hidden files. This technique, often associated with malware families such as TrojanSpy:MSIL/Hakey.A, enables attackers to rename malicious executables (e.g., 'document.pdf.exe') so that the '.exe' extension is invisible to the user. By doing so, the actor increases the likelihood that a victim will inadvertently execute a malicious file while believing it to be a harmless document or benign media file. This activity is persistent in nature and is frequently performed during the initial stages of a compromise or by modular malware payloads to maintain a stealthy presence on the host. Defenders should monitor registry modifications targeting the Explorer Advanced configuration keys for unauthorized changes.

## Attack Chain

1. Initial access is established via a delivery vector such as spearphishing or a drive-by download.
2. The malicious installer or dropper executes in the user context.
3. The malware identifies the target registry path 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced'.
4. The process modifies the 'HideFileExt' registry value to '1' to suppress extension visibility.
5. The process modifies the 'Hidden' registry value to '2' to hide system and hidden files.
6. The adversary drops a payload with a double extension (e.g., 'invoice.pdf.exe').
7. The user interacts with the masqueraded file, believing it to be a legitimate document.
8. Final execution occurs, leading to full system compromise or secondary payload deployment.

## Impact

This technique contributes to successful social engineering, increasing the success rate of malware distribution. It has been observed in various ransomware and infostealer campaigns, allowing attackers to maintain persistence and evade detection by unsuspecting users.

## Recommendation

Prioritize monitoring for unauthorized changes to registry keys governing Windows Explorer visual settings.

- Deploy the provided Sigma rule to detect registry modifications targeting 'HideFileExt' and 'Hidden' keys.
- Audit logs for registry set operations originating from processes in non-standard locations, such as 'C:\Users\Public\' or 'AppData\Local\Temp\'.
- Baseline administrative deployment scripts to identify and allowlist legitimate registry modifications, reducing false positives in the SIEM.
