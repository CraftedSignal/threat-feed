---
title: Monitoring Restoration of Quarantined Files in Microsoft Defender
slug: 2026-09-defender-quarantine-restore
description: This brief documents the detection of file restoration events from the Microsoft Defender quarantine, a technique that can be leveraged by attackers to re-enable malicious payloads.
date: "2026-09-01T12:17:05Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-impairment
  - windows
  - monitoring
affected_os:
  - Windows
references:
  - https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus?view=o365-worldwide
rules:
  - title: Detect Windows Defender Quarantined File Restoration
    description: Detects the restoration of files from the Microsoft Defender quarantine via Event ID 1009
    platform: sigma
    severity: medium
    tactics:
      - defense-impairment
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: monitor_or_close
  owners:
    - SOC
    - Detection Engineering
  hunt_leads:
    - lead: Identify all instances of Event ID 1009 in the last 30 days and correlate with known administrator tickets.
      technique_id: T1685
      data_needed:
        - Windows Defender Operational logs
      priority: medium
      confidence: high
      disposition: convert_to_detection
      evidence: Event ID 1009 indicates a file was restored from quarantine.
---

Monitoring the restoration of files from the Microsoft Defender quarantine is a critical defensive visibility task. While legitimate administrative actions occasionally require restoring a quarantined file, this event is often indicative of post-compromise activity. Attackers who have gained administrative privileges may attempt to restore a file that was previously flagged and isolated by antivirus software to regain access to malicious tools, scripts, or binaries. Because this action effectively disables the protection originally applied by the antimalware platform, security teams should treat unexpected restoration events - particularly those performed by non-administrative service accounts or unauthorized users - as a potential indicator of defense impairment or malicious persistence.

## Impact

Successful restoration of quarantined malicious files can lead to the re-activation of malware, the return of staging tools to the disk, or the recovery of exfiltrated data stored within encrypted payloads. This allows attackers to bypass endpoint security controls that had already correctly identified and blocked the threat, potentially leading to persistent access, data theft, or secondary payload execution.

## Recommendation

Deploy the detection rule provided below to identify instances where the Microsoft Defender antimalware platform restores a file from quarantine. Investigate every trigger of this rule to verify that the file restoration was authorized by a system administrator and aligns with known maintenance windows or incident response procedures.

- Monitor the Microsoft-Windows-Windows Defender/Operational log for Event ID 1009 to track the restoration of quarantined items.
- Establish an allowlist for known administrative accounts and service processes that may legitimately interact with Defender quarantine management APIs.
