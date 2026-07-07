---
title: Suspicious PowerShell Start-Process with PassThru for Stealth Execution
slug: 2026-07-suspicious-start-process-passthru
description: This brief details a PowerShell defense evasion technique where adversaries utilize the `Start-Process` cmdlet with the `-PassThru` parameter to execute commands or programs in a hidden, background manner, enabling covert persistent access or malicious payload execution on Windows systems.
date: "2026-07-03T13:49:11Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - powershell
  - defense-evasion
  - stealth
  - windows
vendors:
  - Microsoft
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
    evidence: 'The technique described in the Sigma rule `Suspicious Start-Process PassThru` is tagged with `attack.t1036.003` (Masquerading: Rename System Utility) and involves PowerShell''s `Start-Process -PassThru` for stealthy execution.'
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_susp_start_process.yml
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1036.003/T1036.003.md
  - https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/start-process?view=powershell-7.6
rules:
  - title: Suspicious PowerShell Start-Process PassThru
    description: Detects PowerShell script blocks using `Start-Process` or its alias `saps` combined with the `-PassThru` and `-FilePath` parameters, which can be used to launch processes in a hidden or background state, often for defense evasion or persistence. Requires PowerShell Script Block Logging.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1036.003
    data_sources:
      - ps_script
      - windows
rules_count: 1
---

This brief describes a PowerShell defense evasion technique observed where adversaries utilize the `Start-Process` cmdlet with the `-PassThru` parameter to execute commands or programs in a hidden manner. This method allows processes to be launched in the background without a visible window or console, making their execution less conspicuous to users and potentially evading detection by security monitoring solutions that rely on visible process creation. The technique is often employed as part of the Masquerading tactic (ATT&CK T1036.003), enabling attackers to blend malicious activity with legitimate system operations or to maintain persistence. The detection rule for this behavior was last modified in May 2026, indicating ongoing relevance and potential use in recent campaigns. This technique bypasses traditional process monitoring by creating processes that are not directly children of the calling PowerShell process, making attribution more challenging.

## Impact

Successful exploitation of this technique primarily enables defense evasion and persistence, allowing attackers to establish covert footholds within compromised systems. By launching malicious processes in a non-interactive, background state, adversaries can execute payloads, establish command and control, or perform data exfiltration without alerting the user. The impact could range from unauthorized access to sensitive data and intellectual property to the deployment of ransomware or other destructive malware, leading to significant financial and operational disruption. Without proper logging and detection, this stealthy execution can prolong the dwell time of an attacker and complicate incident response efforts, making it harder to identify the initial compromise vector and scope of impact.

## Recommendation

*   Enable PowerShell Script Block Logging on all Windows endpoints to ensure the `ScriptBlockText` field is captured for detection.
*   Deploy the "Suspicious PowerShell Start-Process PassThru" Sigma rule in this brief to your SIEM and tune for your environment.
