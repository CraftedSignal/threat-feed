---
title: Windows Defender Real-time Protection Disabled
slug: 2026-09-windows-defender-disabling
description: Detection of unauthorized disabling of Windows Defender real-time protection via system-level service events.
date: "2026-09-01T12:07:40Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-impairment
  - windows-defender
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: Detects disabling of Windows Defender Real-time Protection.
    confidence_band: high
references:
  - https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus?view=o365-worldwide#event-id-5001
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1562.001/T1562.001.md
rules:
  - title: Detect Windows Defender Real-time Protection Disabled
    description: Detects the disabling of Windows Defender real-time protection, which may indicate defensive evasion by an adversary.
    platform: sigma
    severity: medium
    tactics:
      - defense-impairment
    techniques:
      - T1562.001
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: monitor_or_close
  owners:
    - SOC
  hunt_leads:
    - lead: Search for Event ID 5001 to identify potential defense evasion
      technique_id: T1562.001
      data_needed:
        - Windows Event Log
      priority: medium
      confidence: high
      disposition: convert_to_detection
      evidence: Event ID 5001 signifies the disabling of real-time protection
---

Attackers often target security controls to facilitate the execution of malicious payloads, persistence mechanisms, or data exfiltration. Disabling Windows Defender real-time protection (Event ID 5001) is a common defense evasion technique used by adversaries to prevent detection of malware during the post-exploitation phase. This activity is logged by the Windows Defender service and, while it can occasionally be triggered by legitimate administrative activity or automated system updates, it is highly suspicious when occurring in the absence of documented change management. Security teams should monitor for this event to identify unauthorized attempts to weaken host-based defenses.

## Impact

Successful disabling of real-time protection significantly increases the risk of malware infection, unauthorized binary execution, and persistent foothold establishment within the affected host. If left unmonitored, this behavior provides attackers with a window of opportunity to operate undetected.

## Recommendation

* Deploy the Sigma rule below to monitor for Windows Defender service modifications.
* Correlate Event ID 5001 occurrences with other process execution logs (Event ID 4688) to determine if a privileged user or suspicious process initiated the change.
* Audit change management logs for legitimate maintenance windows that might coincide with this event to reduce noise.
