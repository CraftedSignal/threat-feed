---
title: Windows Defender Antivirus Disabled via Registry Modification
slug: 2024-01-disable-defender-registry
description: Attackers modify Windows Defender registry settings to disable antivirus and antispyware protections, evading detection and maintaining persistence.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - defense-evasion
  - registry-modification
  - antivirus
vendors:
  - Microsoft
  - Splunk
products:
  - Windows Defender
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://thedfirreport.com/2021/10/18/icedid-to-xinglocker-ransomware-in-24-hours/
  - https://splunkbase.splunk.com/app/5709
rules:
  - title: Disable AntiSpyware via Registry
    description: Detects modification of the DisableAntiSpyware registry value to disable Windows Defender antispyware.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - registry_set
      - windows
  - title: Disable AntiVirus via Registry
    description: Detects modification of the DisableAntiVirus registry value to disable Windows Defender antivirus.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - registry_set
      - windows
rules_count: 2
---

Attackers commonly disable Windows Defender to evade detection and maintain persistence on compromised systems. This involves modifying specific registry keys associated with Windows Defender policies. The activity is significant because disabling antivirus protections allows attackers to execute further malicious activities undetected, leading to potential data breaches, system compromise, and further propagation of malware within the network. This technique has been observed in campaigns involving malware families such as IcedID, Black Basta ransomware, and Cactus ransomware. Detection of this behavior is crucial for identifying and mitigating potential threats early in the attack chain.

## Attack Chain

1.  Initial access is gained through various methods, such as phishing or exploiting vulnerabilities.
2.  The attacker obtains administrative privileges on the target system.
3.  The attacker uses tools like `reg.exe` or PowerShell to modify the registry.
4.  The registry key `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender` is targeted.
5.  The `DisableAntiSpyware` value is set to `0x00000001` to disable antispyware.
6.  The `DisableAntiVirus` value is set to `0x00000001` to disable antivirus.
7.  Windows Defender is effectively disabled, allowing malware execution without detection.
8.  The attacker proceeds with further malicious activities, such as data exfiltration or ransomware deployment.

## Impact

Successful disabling of Windows Defender can lead to complete system compromise. Attackers can install malware, exfiltrate sensitive data, or deploy ransomware without interference. This can result in significant financial losses, reputational damage, and operational disruption. Observed instances of this technique have been linked to IcedID infections leading to XingLocker ransomware deployment, as well as other ransomware families like Black Basta and Cactus.

## Recommendation

*   Enable Sysmon EventID 13 logging to capture registry modification events.
*   Deploy the Sigma rules provided in this brief to detect the specific registry modifications.
*   Investigate any alerts triggered by the Sigma rules, focusing on the involved processes and users.
*   Review and harden Windows Defender Group Policy settings to prevent unauthorized modifications.
*   Reference the Sigma rule tags to understand which analytic stories are related to this activity (e.g. IcedID, Black Basta, Cactus).
