---
title: Detecting Disabling of Windows Defender Sample Submission
slug: 2024-01-disable-defender-samples
description: An attacker modifies the Windows registry to disable the Windows Defender Submit Samples Consent feature, preventing the submission of suspicious files for analysis, and potentially evading detection.
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
  - Splunk
products:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Windows Defender
references:
  - https://thedfirreport.com/2021/10/18/icedid-to-xinglocker-ransomware-in-24-hours/
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/disable_defender_submit_samples_consent_feature.yml
rules:
  - title: Disable Defender Submit Samples Consent Feature
    description: Detects modification of the Windows registry to disable the Windows Defender Submit Samples Consent feature.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    data_sources:
      - registry_set
      - windows
  - title: Disable Defender Submit Samples Consent Feature - PowerShell
    description: Detects disabling of Windows Defender Submit Samples Consent feature via PowerShell
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers are increasingly targeting endpoint detection capabilities to evade security controls. One specific technique involves disabling Windows Defender's ability to automatically submit samples to Microsoft for analysis. By modifying the `SubmitSamplesConsent` registry value to 0, attackers can prevent suspicious files from being sent for further scrutiny, effectively blinding Defender. This can lead to successful malware execution and system compromise, as seen in incidents involving malware such as IcedID and XingLocker ransomware. This activity has been observed starting in late 2021 and continues to be a relevant evasion tactic. Detecting this registry modification is crucial for maintaining endpoint security.

## Attack Chain

1.  The attacker gains initial access to the system (e.g., via phishing or exploit).
2.  The attacker escalates privileges to gain administrative rights.
3.  The attacker uses a tool like `reg.exe` or PowerShell to modify the registry.
4.  The attacker targets the registry key `HKLM\SOFTWARE\Microsoft\Windows Defender\SpyNet`.
5.  The attacker changes the `SubmitSamplesConsent` value to `0x00000000`.
6.  Windows Defender is now prevented from automatically submitting samples.
7.  The attacker executes malware on the system without automatic sample submission.
8.  The attacker achieves their objective, such as data theft or ransomware deployment.

## Impact

Disabling Windows Defender's sample submission feature allows attackers to execute malicious code undetected. This can lead to data breaches, system compromise, and ransomware infections. The DFIR Report has documented instances where disabling AV features was a critical step in successful ransomware attacks. Organizations that fail to detect this activity are at increased risk of significant financial and operational damage.

## Recommendation

*   Enable Sysmon EventID 13 to monitor registry modifications (data_source).
*   Deploy the Sigma rule "Disable Defender Submit Samples Consent Feature" to detect the registry modification (rules).
*   Investigate any endpoint where the `SubmitSamplesConsent` registry value is set to `0x00000000` in the specified registry path (search).
*   Ensure Sysmon TA version 2.0 or later is installed for proper log ingestion (how_to_implement).
