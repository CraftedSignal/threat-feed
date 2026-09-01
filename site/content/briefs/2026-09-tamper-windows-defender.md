---
title: PowerShell Defense Impairment via Set-MpPreference
slug: 2026-09-tamper-windows-defender
description: Adversaries utilize PowerShell's Set-MpPreference cmdlet to disable Windows Defender security features and modify threat handling behavior, facilitating persistence and stealth.
date: "2026-09-01T12:08:20Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - defense-impairment
  - windows
  - powershell
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: Detects PowerShell scripts attempting to disable scheduled scanning and other parts of Windows Defender ATP or set default actions to allow.
    confidence_band: high
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1562.001/T1562.001.md
  - https://learn.microsoft.com/en-us/powershell/module/defender/set-mppreference?view=windowsserver2022-ps
rules:
  - title: Detect Tampering of Windows Defender via Set-MpPreference
    description: Detects PowerShell scripts attempting to disable scheduled scanning, real-time monitoring, or other Windows Defender protections, as well as modifying threat actions to allow.
    platform: sigma
    severity: high
    tactics:
      - defense-impairment
    data_sources:
      - ps_script
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the provided Sigma rule to detect defense impairment attempts.
      owner: Detection Engineering
      due: 24h
      evidence: Sigma rule provided in brief.
  hunt_leads:
    - lead: Search for historical Event ID 4104 logs containing 'Set-MpPreference' followed by modification flags.
      technique_id: T1562.001
      data_needed:
        - Event ID 4104 logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source explicitly documents the usage of Set-MpPreference for tampering.
  mitigation_plan:
    - priority: immediate
      action: Enable PowerShell Script Block Logging (Event ID 4104) via GPO.
      owner: IT Operations
      addresses: Defense impairment visibility
      evidence: Source requires Script Block Logging.
---

Adversaries frequently target security software to minimize detection risks during post-exploitation activities. A common technique involves abusing the native PowerShell cmdlet 'Set-MpPreference' to impair Windows Defender. By modifying preference parameters, an attacker can disable essential security components such as real-time monitoring, intrusion prevention, script scanning, and behavior monitoring. Additionally, attackers can downgrade the default actions taken upon detecting threats, effectively instructing the security engine to 'Allow' malicious activity. This technique is typically employed following initial access, once the attacker has gained administrative privileges required to interact with the Defender configuration API. Defenders should monitor PowerShell Script Block Logging events for the usage of these specific modification flags to identify unauthorized defense impairment attempts.

## Attack Chain

1. Attacker achieves initial access on a Windows endpoint.
2. Attacker escalates privileges to local administrator or SYSTEM to gain configuration access.
3. Attacker identifies the security suite as Windows Defender (Microsoft Defender Antivirus).
4. Attacker launches a PowerShell process to interact with the Windows Defender WMI namespace.
5. Attacker executes 'Set-MpPreference' with flags such as '-DisableRealtimeMonitoring $true' or '-DisableBehaviorMonitoring $true'.
6. Attacker modifies threat response settings (e.g., 'HighThreatDefaultAction Allow') to ensure future malicious payloads are ignored.
7. Attacker proceeds with further activity, such as deploying ransomware or backdoors, without intervention from the antivirus engine.

## Impact

Successful execution of this technique results in the neutralization of the primary endpoint security controls. This allows attackers to execute, move laterally, and exfiltrate data while remaining invisible to Windows Defender alerts. The impact includes unhindered deployment of secondary malware, loss of data integrity, and prolonged dwell time within the targeted environment.

## Recommendation

Prioritize the implementation of PowerShell Script Block Logging across all Windows endpoints to capture the specific command-line arguments mentioned in this brief. Deploy the provided Sigma rule to alert on unauthorized configuration changes to the antivirus agent. Investigate any instances where 'Set-MpPreference' is invoked outside of defined maintenance windows or sanctioned administrative scripts.
