---
title: Disabling CMD Application via Registry Modification
slug: 2024-01-03-disabling-cmd
description: Attackers modify the Windows registry to disable the command prompt (cmd.exe), hindering incident response and potentially maintaining persistence.
date: "2024-01-03T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - registry-modification
  - defense-evasion
  - windows
vendors:
  - Microsoft
  - Splunk
products:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1112
    technique_name: Modify Registry
references:
  - https://any.run/report/ea4ea08407d4ee72e009103a3b77e5a09412b722fdef67315ea63f22011152af/a866d7b1-c236-4f26-a391-5ae32213dfc4#registry
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/disabling_cmd_application.yml
rules:
  - title: Detect Disabling CMD via Registry Modification
    description: Detects modifications to the registry to disable the CMD application.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1112
    data_sources:
      - registry_set
      - windows
  - title: Detect Disabling CMD via Registry Modification - Sysmon Event ID 13
    description: Detects modifications to the registry to disable the CMD application using Sysmon Event ID 13.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1112
    data_sources:
      - file_event
      - windows
rules_count: 2
---

Attackers, including those deploying remote access trojans (RATs), Trojans, or Worms, may attempt to disable the Windows command prompt (cmd.exe) to impair incident response capabilities. This is achieved by modifying the `DisableCMD` registry value, preventing analysts from using CMD for investigation and remediation. The technique directly impacts an organization's ability to perform tasks such as directory and file traversal, potentially granting the attacker extended persistence within the compromised environment. Disabling CMD can significantly complicate security teams' efforts to contain and eradicate threats.

## Attack Chain

1.  The attacker gains initial access to the system, potentially through phishing or exploiting a vulnerability.
2.  The attacker escalates privileges to make changes to the registry.
3.  The attacker modifies the registry key `HKLM\SOFTWARE\Policies\Microsoft\Windows\System` or `HKCU\SOFTWARE\Policies\Microsoft\Windows\System`.
4.  The attacker sets the `DisableCMD` registry value to `0x00000001` (DWORD).
5.  The system interprets this change and disables the command prompt.
6.  Security analysts attempt to use `cmd.exe` for incident response but are blocked.
7.  The attacker maintains persistence due to the reduced visibility and control of the compromised system by security personnel.

## Impact

Disabling the command prompt hinders incident response efforts by preventing analysts from using essential tools for investigation and remediation. This can lead to delayed detection and containment, potentially allowing the attacker to maintain persistence, move laterally within the network, and exfiltrate sensitive data. The impact can range from prolonged downtime to data breaches, depending on the attacker's objectives.

## Recommendation

*   Enable Sysmon EventID 13 to monitor registry modifications, specifically changes to the `DisableCMD` registry value as described in the overview.
*   Deploy the Sigma rules provided to detect malicious modifications to the `DisableCMD` registry value in your SIEM.
*   Investigate any detected instances of `DisableCMD` registry value changes, especially if the user or process involved is not an authorized administrator.
*   If confirmed malicious, investigate the source and scope of the breach.
