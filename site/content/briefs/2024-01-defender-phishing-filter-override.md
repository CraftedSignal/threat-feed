---
title: Windows Defender Phishing Filter Override via Registry Modification
slug: 2024-01-defender-phishing-filter-override
description: The analytic detects modifications to the Windows registry that disable the Windows Defender phishing filter, potentially allowing attackers to deceive users into visiting malicious websites without browser warnings.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - defense-evasion
  - windows
  - registry-abuse
vendors:
  - Microsoft
  - Splunk
products:
  - Microsoft Edge
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://x.com/malmoeb/status/1742604217989415386?s=20
  - https://github.com/undergroundwires/privacy.sexy
rules:
  - title: Windows Defender Phishing Filter Override via Registry Modification
    description: Detects modifications to the Windows Registry that disable the Windows Defender phishing filter.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - registry_set
      - windows
  - title: Process Modifying Windows Defender Phishing Filter Registry
    description: Detects processes modifying registry keys related to Windows Defender phishing filter.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This detection focuses on identifying attempts to disable the Windows Defender phishing filter by modifying specific registry values. Attackers may attempt to disable this security feature to increase the likelihood of successful phishing attacks, where users are tricked into visiting malicious websites. The detection leverages Sysmon Event ID 13 to monitor changes to registry values associated with Microsoft Edge's phishing filter settings. Disabling this filter allows malicious actors to deceive users into visiting harmful websites without triggering browser warnings. This can lead to potential security incidents, such as malware infections or credential theft, if users unknowingly access compromised sites.

## Attack Chain

1.  An attacker gains initial access through social engineering or other means.
2.  The attacker obtains administrative privileges on the target system, if necessary.
3.  The attacker uses a script or command-line tool (e.g., `reg.exe`, PowerShell) to modify the Windows Registry.
4.  The script or command modifies the registry key `HKLM\SOFTWARE\Policies\Microsoft\Edge\PhishingFilter` or `HKCU\SOFTWARE\Microsoft\Edge\PhishingFilter`.
5.  The registry value "EnabledV9" or "PreventOverride" is set to "0x00000000" to disable the phishing filter.
6.  The attacker verifies that the phishing filter is disabled in Microsoft Edge.
7.  The attacker launches a phishing campaign, directing users to malicious websites.
8.  Users, unaware of the disabled phishing filter, may visit the malicious websites, potentially leading to malware infection or data compromise.

## Impact

Successful disabling of the Windows Defender phishing filter can significantly increase the risk of successful phishing attacks. Users may unknowingly visit malicious websites, leading to malware infections, credential theft, or other data compromises. This can result in financial losses, reputational damage, and disruption of business operations. While the exact number of potential victims is unknown, the impact could be widespread if the attack is successful on multiple systems within an organization.

## Recommendation

*   Enable Sysmon Event ID 13 to collect registry modification events, as this is required for the detections in this brief.
*   Deploy the Sigma rule "Windows Defender Phishing Filter Override via Registry Modification" to your SIEM and tune for your environment.
*   Investigate any detected instances of registry modifications to the `*\MicrosoftEdge\PhishingFilter*` path, especially when `registry_value_data` is set to "0x00000000".
*   Educate users about the risks of phishing attacks and encourage them to be cautious when clicking on links or opening attachments from unknown sources.
