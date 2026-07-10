---
title: Shadow Copy Deletion via VSSAdmin or WMIC
slug: 2024-01-shadow-copy-deletion
description: Attackers delete shadow copies using vssadmin.exe or wmic.exe to prevent data recovery, often preceding ransomware deployment or data exfiltration.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - shadow-copy
  - anti-forensic
  - ransomware
  - windows
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1490
    technique_name: Inhibit System Recovery
references:
  - https://blogs.vmware.com/security/2022/10/lockbit-3-0-also-known-as-lockbit-black.html
rules:
  - title: Detect Shadow Copy Deletion via VSSAdmin
    description: Detects shadow copy deletion using vssadmin.exe.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1490
    data_sources:
      - process_creation
      - windows
  - title: Detect Shadow Copy Deletion via WMIC
    description: Detects shadow copy deletion using wmic.exe.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1490
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers frequently delete shadow copies on Windows systems to hinder data recovery efforts. This tactic is often observed in ransomware attacks, where the ability to restore from backups is crucial for victims. This activity is typically carried out using legitimate system utilities such as vssadmin.exe or wmic.exe. Endpoint Detection and Response (EDR) agents are essential for detecting this activity. The use of command-line arguments containing "delete" and "shadow" are indicators of malicious intent. This behavior is particularly concerning as it directly impedes incident response and recovery capabilities, allowing attackers to maximize the impact of their operations. The detection focuses on process names and command-line arguments.

## Attack Chain

1. Initial access is gained through various means, such as exploiting vulnerabilities or phishing campaigns (not explicitly covered in source).
2. The attacker obtains elevated privileges on the compromised system.
3. The attacker uses vssadmin.exe to list existing shadow copies: `vssadmin list shadows`.
4. The attacker uses vssadmin.exe to delete shadow copies: `vssadmin.exe delete shadows /all /quiet`.
5. Alternatively, the attacker may use wmic.exe to delete shadow copies: `wmic.exe shadowcopy delete`.
6. After deleting shadow copies, the attacker deploys ransomware or exfiltrates sensitive data.
7. The attacker may further attempt to disable system recovery options to solidify their control.
8. The final objective is to extort a ransom payment from the victim or sell stolen data.

## Impact

Successful deletion of shadow copies severely impairs a victim's ability to recover from ransomware attacks or data breaches. The inability to restore from shadow copies often forces organizations to pay ransom demands, leading to significant financial losses and reputational damage. The LockBit 3.0 ransomware group, among others, has been observed using this technique. This can also lead to data loss.

## Recommendation

*   Enable Sysmon process creation logging to capture command-line arguments (Sysmon EventID 1).
*   Enable Windows Event Log Security logging, specifically event ID 4688, to capture process creation events.
*   Deploy the Sigma rule "Detect Shadow Copy Deletion via VSSAdmin" to your SIEM and tune for your environment.
*   Deploy the Sigma rule "Detect Shadow Copy Deletion via WMIC" to your SIEM and tune for your environment.
*   Investigate any instances of vssadmin.exe or wmic.exe executing with command-line arguments containing "delete" and "shadow".
