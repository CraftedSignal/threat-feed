---
title: Detection of Suspicious PowerShell WindowStyle Hidden Usage
slug: 2026-09-suspicious-powershell-windowstyle
description: Adversaries utilize the PowerShell WindowStyle parameter to execute scripts in a hidden window, a technique often used to conceal malicious activity from user visibility.
date: "2026-09-03T13:43:09Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - stealth
  - powershell
  - execution
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1564
    technique_name: Hide Artifacts
    evidence: Adversaries may use hidden windows to conceal malicious activity from the plain sight of users.
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_susp_windowstyle.yml
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1564.003/T1564.003.md
rules:
  - title: Detect Suspicious PowerShell WindowStyle Hidden Usage
    description: Detects the use of PowerShell -WindowStyle Hidden, which is commonly used to conceal malicious activity from user visibility.
    platform: sigma
    severity: medium
    tactics:
      - stealth
    techniques:
      - T1564.003
    data_sources:
      - ps_script
      - windows
rules_count: 1
action_plan:
  priority: monitor_or_close
  owners:
    - Detection Engineering
  hunt_leads:
    - lead: Search for historical instances of WindowStyle Hidden in logs to baseline normal behavior
      technique_id: T1564.003
      data_needed:
        - PowerShell Event ID 4104 logs
      priority: medium
      confidence: medium
      disposition: convert_to_detection
      evidence: Adversaries use hidden windows for stealth.
---

Adversaries frequently employ the PowerShell -WindowStyle Hidden parameter to execute malicious scripts while minimizing the visible footprint on the target system. By suppressing the appearance of the PowerShell console window, attackers can conduct background operations, such as downloading and executing payloads, credential dumping, or lateral movement, without alerting the active user. This behavior is a common component of various post-exploitation toolkits and persistent threats. Defenders should focus on Script Block Logging (Event ID 4104) to capture and inspect the specific commands executed within PowerShell, as attackers often attempt to blend these commands into legitimate administrative or automation scripts.

## Impact

Successful abuse of hidden window execution allows attackers to maintain stealth during the execution of malicious code. If undetected, this can lead to full system compromise, data exfiltration, or the establishment of long-term persistence in the target environment, significantly reducing the probability of immediate user-driven incident response.

## Recommendation

Detection engineering teams should focus on identifying PowerShell script blocks containing the combination of WindowStyle and Hidden keywords. 

- Enable PowerShell Script Block Logging (Event ID 4104) across the environment to provide the visibility required for the Sigma rule below.
- Deploy the provided Sigma rule to your SIEM and tune it against known administrative automation scripts that legitimately use the Hidden parameter.
- Investigate any hits from this rule to determine if the originating process is a standard deployment script or an unauthorized malicious actor.
