---
title: Windows Defender Submit Samples Consent Feature Disabled via Registry Modification
slug: 2024-01-03-disable-defender-submit-samples
description: Attackers modify the Windows Registry to disable the Windows Defender Submit Samples Consent feature, preventing sample submission for analysis and enabling potential system compromise.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - defense-evasion
  - registry-modification
  - windows-defender
vendors:
  - Microsoft
products:
  - Windows Defender
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://thedfirreport.com/2021/10/18/icedid-to-xinglocker-ransomware-in-24-hours/
rules:
  - title: Detect Disable Windows Defender Submit Samples Consent via Registry
    description: Detects modification of the Windows Registry to disable the Windows Defender Submit Samples Consent feature.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - registry_set
      - windows
  - title: Detect Registry Modification to Disable Sample Submission (Generic)
    description: Detects generic registry modification events that could indicate an attempt to disable sample submission features.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - registry_set
      - windows
rules_count: 2
---

Attackers disable the Windows Defender Submit Samples Consent feature by modifying a specific registry key, as observed in IcedID and XingLocker ransomware campaigns. This activity prevents Windows Defender from automatically submitting suspicious files to Microsoft for analysis, allowing malware to potentially evade detection. The targeted registry path is associated with Windows Defender SpyNet, and the value of 'SubmitSamplesConsent' is set to '0x00000000'. Disabling this feature significantly reduces the effectiveness of Windows Defender, increasing the risk of successful malware execution and system compromise.

## Attack Chain

1. Initial Access: The attacker gains initial access to the system through methods such as phishing emails, or exploitation of existing vulnerabilities.
2. Privilege Escalation: The attacker escalates privileges to gain administrative rights, allowing modification of sensitive system settings.
3. Persistence: The attacker establishes persistence on the system to maintain access, potentially using techniques like creating scheduled tasks or modifying registry keys.
4. Defense Evasion: The attacker modifies the registry to disable the Windows Defender Submit Samples Consent feature, specifically targeting the 'SubmitSamplesConsent' value under the 'HKLM\SOFTWARE\Microsoft\Windows Defender\SpyNet' registry key.
5. Malware Deployment: The attacker deploys and executes malicious payloads, taking advantage of the weakened defense posture.
6. Lateral Movement: The attacker moves laterally within the network, compromising additional systems.
7. Data Exfiltration/Encryption: The attacker exfiltrates sensitive data or encrypts files for ransom, depending on the objective.
8. Impact: System compromise, data theft, or encryption leading to operational disruption and financial loss.

## Impact

Disabling the Submit Samples Consent feature weakens Windows Defender's ability to detect and respond to emerging threats. A successful attack can lead to widespread malware infection, data breaches, and significant operational disruption. This technique has been observed in campaigns involving IcedID and XingLocker ransomware, demonstrating its potential for severe impact.

## Recommendation

*   Enable Sysmon Event ID 13 to monitor registry modifications and ensure the Sysmon TA is version 2.0 or later.
*   Deploy the Sigma rule "Detect Disable Windows Defender Submit Samples Consent via Registry" to your SIEM and tune for your environment.
*   Investigate any detected instances of registry modifications to the 'HKLM\SOFTWARE\Microsoft\Windows Defender\SpyNet\SubmitSamplesConsent' key with a value of '0x00000000' for suspicious activity.
*   Refer to the provided references (https://thedfirreport.com/2021/10/18/icedid-to-xinglocker-ransomware-in-24-hours/) for additional context on real-world exploitation of this technique.
