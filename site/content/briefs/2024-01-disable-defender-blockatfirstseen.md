---
title: Windows Defender BlockAtFirstSeen Feature Disabled via Registry Modification
slug: 2024-01-disable-defender-blockatfirstseen
description: An attacker modifies the Windows Registry to disable the Windows Defender BlockAtFirstSeen feature, potentially allowing malware to bypass initial detection and increasing the risk of system compromise.
date: "2024-01-03T12:00:00Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
tags:
  - registry_modification
  - defender
  - blockatfirstseen
vendors:
  - Microsoft
  - Splunk
products:
  - Windows Defender
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
references:
  - https://thedfirreport.com/2021/10/18/icedid-to-xinglocker-ransomware-in-24-hours/
  - https://splunkbase.splunk.com/app/5709
rules:
  - title: Registry Modification to Disable BlockAtFirstSeen
    description: Detects modification of the DisableBlockAtFirstSeen registry value to disable the Windows Defender feature.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    data_sources:
      - registry_set
      - windows
  - title: Process Modifying Defender BlockAtFirstSeen Registry
    description: Detects processes that are modifying the DisableBlockAtFirstSeen registry value.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This threat brief addresses the disabling of the Windows Defender BlockAtFirstSeen feature through registry modification. The BlockAtFirstSeen feature provides initial protection against new and unknown threats. Attackers may disable this feature to bypass these initial detection mechanisms, increasing the likelihood of successful malware execution and subsequent system compromise. The analytic detects modifications to the `DisableBlockAtFirstSeen` registry value under the `Microsoft\Windows Defender\SpyNet` path. The activity is significant because it weakens the endpoint's security posture, creating an opportunity for malware to execute undetected. Observed in attacks such as IcedID, this technique can lead to ransomware deployment and data breaches.

## Attack Chain

1.  Initial access is gained through methods such as phishing or exploitation of vulnerabilities.
2.  The attacker executes code on the target system.
3.  The attacker identifies the registry key associated with Windows Defender SpyNet: `HKLM\SOFTWARE\Microsoft\Windows Defender\SpyNet`.
4.  The attacker modifies the `DisableBlockAtFirstSeen` value within the SpyNet registry key.
5.  The `DisableBlockAtFirstSeen` value is set to `0x00000001` to disable the feature.
6.  Windows Defender no longer blocks the execution of files based on reputation.
7.  The attacker executes malicious payloads that would normally be blocked.
8.  The attacker achieves their objective, such as deploying ransomware, exfiltrating data, or establishing persistence.

## Impact

Disabling the BlockAtFirstSeen feature significantly reduces the effectiveness of Windows Defender, potentially exposing systems to new and unknown malware threats. Successful exploitation can lead to malware infection, system compromise, data breaches, and ransomware deployment. The DFIR Report has observed this technique being used in conjunction with IcedID leading to Xinglocker ransomware deployment.

## Recommendation

*   Deploy the Sigma rule `Registry Modification to Disable BlockAtFirstSeen` to your SIEM to detect this specific registry modification.
*   Enable Sysmon Event ID 13 (Registry Event) logging to collect the necessary data for the Sigma rules.
*   Investigate any detected instances of `DisableBlockAtFirstSeen` registry value modification, prioritizing those occurring on critical systems.
*   Enforce strict access control policies to prevent unauthorized modification of registry settings.
*   Monitor systems for signs of malware infection following any detected attempts to disable the BlockAtFirstSeen feature.
