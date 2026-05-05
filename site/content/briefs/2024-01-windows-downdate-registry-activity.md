---
title: Windows Downdate Attack Registry Modification
slug: 2024-01-windows-downdate-registry-activity
description: The Windows Downdate attack involves modifying specific registry keys to force a Windows downgrade, enabling exploitation of older, vulnerable versions, which this detection identifies through monitoring for the creation or modification of the pending.xml file in unusual locations.
date: "2024-01-03T18:12:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - privilege-escalation
  - windows
  - registry-modification
vendors:
  - Splunk
products:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1112
    technique_name: Modify Registry
references:
  - https://www.safebreach.com/blog/downgrade-attacks-using-windows-updates/
rules:
  - title: Detect Windows Downdate Registry Activity
    description: Detects modifications to registry keys associated with the Windows Downdate attack, specifically targeting PoqexecCmdline and COMPONENTS\PendingXmlIdentifier outside of the WinSxS directory.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1112
    data_sources:
      - registry_set
      - windows
  - title: Detect Windows Downdate Registry Activity (Process Path Filter)
    description: Detects modifications to registry keys associated with the Windows Downdate attack, specifically targeting PoqexecCmdline and COMPONENTS\PendingXmlIdentifier. Filters out known legitimate process paths.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1112
    data_sources:
      - registry_set
      - windows
rules_count: 2
---

The Windows Downdate attack is a technique used by attackers to revert a system to an earlier, more vulnerable version of Windows. This is achieved by manipulating specific registry keys and files associated with the Windows Update process, specifically the `pending.xml` file. By forcing a downgrade, attackers can bypass security mitigations present in newer operating systems and exploit known vulnerabilities that have been patched in later versions. This detection focuses on identifying anomalous registry activity related to the `pending.xml` file, specifically when it occurs outside of the expected `WinSxS` directory. This activity can indicate an attempt to manipulate the update process and facilitate a downgrade attack. This is important for defenders because a successful downgrade can significantly weaken a system's security posture.

## Attack Chain

1.  The attacker gains initial access to the target system (e.g., through phishing or exploiting a remote vulnerability).
2.  The attacker obtains elevated privileges on the system.
3.  The attacker modifies the registry to manipulate the Windows Update process, targeting keys like `PoqexecCmdline` or `COMPONENTS\\PendingXmlIdentifier`.
4.  The attacker crafts or modifies a `pending.xml` file in a non-standard location outside of the `WinSxS` directory.
5.  The system is rebooted, triggering the Windows Update process to read the modified `pending.xml` file.
6.  The modified `pending.xml` instructs the system to downgrade to a previous version of Windows.
7.  After the downgrade is complete, the attacker exploits known vulnerabilities present in the older Windows version.
8.  The attacker achieves their final objective, such as installing malware, stealing sensitive data, or establishing persistence.

## Impact

A successful Windows Downdate attack can have significant consequences. It can allow attackers to bypass security mitigations, exploit known vulnerabilities, and gain unauthorized access to sensitive data. The impact of such an attack can range from data breaches and financial losses to reputational damage and system compromise. While the number of victims and specific sectors targeted by this technique are not explicitly available, the potential for widespread impact is high, given the prevalence of Windows systems.

## Recommendation

*   Enable Sysmon EventID 12, 13, and 14 to monitor registry modifications related to the Windows Update process, as outlined in the data source section.
*   Deploy the Sigma rule `Detect Windows Downdate Registry Activity` to identify suspicious modifications to the `PoqexecCmdline` or `COMPONENTS\\PendingXmlIdentifier` registry keys.
*   Investigate any alerts triggered by the Sigma rule, focusing on instances where the `pending.xml` file is created or modified outside of the `C:\\Windows\\WinSxS\\` directory.
*   Implement change management processes to track and validate legitimate system updates or rollback processes to minimize false positives, as described in the known false positives section.
