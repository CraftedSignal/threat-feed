---
title: Detection of Windows Defender Real-time Protection Impairment
slug: 2026-09-windows-defender-disabled
description: This brief documents the detection logic for identifying when Windows Defender anti-malware scanning is disabled, a common TTP used by adversaries to impair system defenses.
date: "2026-09-01T12:07:48Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - defense-impairment
  - windows
  - security-telemetry
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: Detects disabling of the Windows Defender virus scanning feature.
    confidence_band: high
references:
  - https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus?view=o365-worldwide#event-id-5012
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1562.001/T1562.001.md
rules:
  - title: Detect Windows Defender Virus Scanning Disabled
    description: Detects Event ID 5012, indicating that the Windows Defender virus scanning feature has been disabled.
    platform: sigma
    severity: high
    tactics:
      - defense-impairment
    techniques:
      - T1562.001
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the provided Sigma rule to detect and alert on Event ID 5012.
      owner: Detection Engineering
      due: 24h
      evidence: Source documentation for Event ID 5012 indicates defensive impairment.
  hunt_leads:
    - lead: Search for logs where Event ID 5012 is followed by unexpected process activity.
      technique_id: T1562.001
      data_needed:
        - Event log ingestion
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Defender disabling is a precursor to malicious activity.
---

Adversaries often attempt to disable security software to facilitate the deployment of malware, ransomware, or persistence mechanisms without triggering heuristic or signature-based alerts. Disabling Windows Defender specifically allows attackers to move laterally, execute malicious payloads, or establish command-and-control communication with reduced risk of detection. Monitoring for the deactivation of antivirus features is a critical component of a robust defense-in-depth strategy. This brief focuses on detecting Microsoft-Windows-Windows Defender Event ID 5012, which indicates that the scanning engine has been turned off. This event is typically generated following administrative actions or malicious modifications to Windows registry keys and security settings. Detection engineers should ensure that these events are forwarded to their security information and event management (SIEM) systems to alert on unauthorized changes to anti-malware configurations.

## Impact

Successful impairment of Windows Defender significantly lowers the security posture of an endpoint, rendering the system vulnerable to a wide range of exploits and malicious payloads that would otherwise be blocked. If the feature is disabled, attackers can perform post-exploitation activities, including credential dumping, persistence installation, and data exfiltration, with a much higher probability of evading detection. This technique is frequently observed across various campaigns targeting Windows environments to ensure persistent access and stealthy execution.

## Recommendation

- Enable collection of Microsoft-Windows-Windows Defender/Operational logs in all Windows endpoints.
- Implement the provided Sigma rule to alert on Event ID 5012, which signifies a high-severity security configuration change.
- Investigate the source of any Event ID 5012 to determine if it resulted from authorized system administration or unauthorized malicious activity.
- Establish a baseline of authorized software deployment and maintenance activities to tune out expected occurrences of antivirus service configuration changes.
