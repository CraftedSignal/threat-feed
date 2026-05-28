---
title: Windows Registry Modification Risk Behavior Detection
slug: 2026-05-windows-registry-risk
description: This analytic identifies instances where three or more distinct registry modification events associated with MITRE ATT&CK Technique T1112 are detected, leveraging Splunk's Risk data model to detect persistence, hiding malicious configurations, or erasing forensic evidence.
date: "2026-05-28T17:46:27Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - registry
  - persistence
  - defense-evasion
  - windows
vendors:
  - Splunk
products:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1112
    technique_name: Modify Registry
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1112
    technique_name: Modify Registry
references:
  - https://www.splunk.com/en_us/blog/security/do-not-cross-the-redline-stealer-detections-and-analysis.html
  - https://www.splunk.com/en_us/blog/security/asyncrat-crusade-detections-and-defense.html
  - https://www.splunk.com/en_us/blog/security/from-registry-with-love-malware-registry-abuses.html
  - https://www.splunk.com/en_us/blog/security/-applocker-rules-as-defense-evasion-complete-analysis.html
rules:
  - title: Detect Multiple Registry Modifications in Short Timeframe
    description: Detects a host modifying multiple registry keys within a short timeframe, potentially indicative of malicious activity.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - persistence
    techniques:
      - T1112
    data_sources:
      - registry_set
      - windows
  - title: Detect Registry Key Modification to Disable Security Features
    description: Detects modification of specific registry keys commonly targeted by malware to disable security features.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1112
      - T1562.001
    data_sources:
      - registry_set
      - windows
rules_count: 2
---

This detection identifies suspicious behavior related to multiple registry modifications on Windows systems. The detection focuses on identifying hosts with three or more distinct registry modification events associated with MITRE ATT&CK Technique T1112 (Modify Registry). The detection leverages data from Splunk's Risk data model, emphasizing registry-related sources and MITRE technique annotations. This type of activity is often associated with malware persistence, hiding malicious configurations, or erasing forensic evidence to evade detection. This behavior is a strong indicator of potential compromise and requires further investigation to determine the extent of the malicious activity.

## Attack Chain

1.  Initial access is gained through various means such as exploiting a vulnerability, or social engineering.
2.  Malware is executed on the system, initiating the malicious activity.
3.  The malware modifies the Windows Registry to establish persistence.
4.  The malware may also modify registry keys to disable security features or hide its presence.
5.  The attacker uses registry modifications to maintain persistent access to the compromised system.
6.  The system may be used to execute malicious code, gather sensitive information, or move laterally within the network.

## Impact

Successful exploitation can lead to persistent access for attackers, allowing them to execute malicious code, steal sensitive information, and potentially move laterally within the network. This can result in data breaches, financial loss, and reputational damage for the organization. The number of affected systems depends on the scope of the initial compromise and the attacker's ability to spread within the network. The damage includes potential data exfiltration, system instability, and the installation of backdoors for future access.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM and tune based on your environment to detect multiple registry modifications related to MITRE ATT&CK Technique T1112.
*   Investigate any hosts triggering this alert to determine the root cause and scope of the malicious activity.
*   Implement endpoint detection and response (EDR) solutions to provide real-time visibility and control over registry modifications.
*   Ensure that systems are patched and up-to-date to prevent exploitation of known vulnerabilities (related to initial access).
