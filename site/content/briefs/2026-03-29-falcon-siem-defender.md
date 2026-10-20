---
brief_id: brief-2026-03-29-falcon-siem-defender
event_id: brief-2026-03-29-falcon-siem-defender
revision: 2
activity_at: "2026-03-29T10:38:33Z"
revision_history:
  - revision: 2
    at: "2026-10-20T13:19:21Z"
    checksum: sha256:b297b139be54d77cb76a74cab66441ba906330cc0276cfddcd6a49c1784fbdfc
    summary: Repaired a legacy canonical identity collision
    changed_fields:
      - slug
    maintenance: true
title: CrowdStrike Falcon Next-Gen SIEM Integrates with Microsoft Defender
slug: 2026-03-29-falcon-siem-defender
description: CrowdStrike's Falcon Next-Gen SIEM expands its capabilities to support third-party EDR solutions, starting with Microsoft Defender, aiming to unify security operations and reduce data management overhead for organizations using diverse endpoint protection tools.
date: "2026-03-29T10:38:33Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
tags:
  - siem
  - edr
  - microsoft-defender
  - crowdstrike-falcon
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1027
    technique_name: Obfuscated Files or Information
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
references:
  - https://www.crowdstrike.com/en-us/blog/falcon-next-gen-siem-supports-third-party-edr-tools-starting-with-microsoft-defender/
rules:
  - title: Detect Suspicious PowerShell Command via Defender
    description: Detects suspicious PowerShell commands observed by Microsoft Defender and ingested into Falcon SIEM.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
  - title: Detect Credential Dumping via Defender Telemetry
    description: Detects attempts to dump credentials from LSASS, as reported through Defender telemetry in Falcon SIEM.
    platform: sigma
    severity: critical
    tactics:
      - credential_access
    techniques:
      - T1003.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

CrowdStrike's Falcon Next-Gen SIEM is evolving to support third-party EDR solutions, beginning with Microsoft Defender. Announced on March 23, 2026, this enhancement enables organizations to integrate Microsoft Defender telemetry into the Falcon SIEM without requiring the Falcon sensor on those endpoints. This allows for a more unified security operations center (SOC) by combining data from different sources into a single platform. The goal is to streamline threat detection, investigation, and response across diverse environments, addressing the challenges of fragmented security systems and data visibility tradeoffs. The integration aims to eliminate the "data tax" associated with ingesting large volumes of security data while accelerating security outcomes through AI-native threat detection and automation.

## Attack Chain

This brief focuses on improving detection capabilities rather than describing a specific attack chain. The goal is to enhance visibility across different EDR solutions. A hypothetical chain, leveraging the integrated visibility, could involve:

1.  **Initial Access (Phishing):** An attacker gains initial access via a phishing email.
2.  **Execution (PowerShell):** The user clicks a malicious link, and a PowerShell script is executed.
3.  **Defense Evasion (Obfuscation):** The PowerShell script uses obfuscation techniques to evade detection. Microsoft Defender detects this behavior and logs it.
4.  **Credential Access (LSASS):** The script attempts to dump credentials from LSASS.
5.  **Lateral Movement (SMB):** The attacker uses stolen credentials to move laterally to other systems via SMB.
6.  **Command and Control (C2):** A reverse shell is established to a C2 server.
7.  **Data Exfiltration (Rclone):** Sensitive data is exfiltrated using Rclone.
8.  **Impact:** Data is sold on the dark web or used for further malicious activities.

## Impact

The integration of Microsoft Defender data into CrowdStrike Falcon Next-Gen SIEM aims to reduce the impact of attacks by providing a more comprehensive view of the threat landscape. Without such integration, organizations might experience slower detection times, increased investigation efforts, and a higher risk of successful breaches due to fragmented visibility. By unifying data from multiple EDR solutions, organizations can improve their ability to detect and respond to sophisticated attacks, potentially preventing data breaches, ransomware incidents, and other security incidents.

## Recommendation

*   Deploy the provided Sigma rules to your CrowdStrike Falcon Next-Gen SIEM to detect malicious activities observed by Microsoft Defender and other integrated EDR solutions.
*   Configure Microsoft Defender to send its telemetry to CrowdStrike Falcon Next-Gen SIEM to take advantage of unified detection and response capabilities.
*   Utilize Falcon Onum's data filtering and enrichment capabilities to reduce noise and improve the quality of data ingested into the SIEM.
*   Implement federated search to investigate across live, network, and archived data sources without costly re-ingestion.
