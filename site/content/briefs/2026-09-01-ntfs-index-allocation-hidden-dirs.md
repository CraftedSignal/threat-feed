---
title: Abuse of NTFS INDEX_ALLOCATION Stream for Directory Obfuscation
slug: 2026-09-01-ntfs-index-allocation-hidden-dirs
description: Attackers can abuse the NTFS $INDEX_ALLOCATION stream to create directories that are inaccessible to standard Windows utilities like Explorer and PowerShell, facilitating stealthy data storage.
date: "2026-09-01T12:25:07Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - stealth
  - persistence
  - windows
  - ntfs
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1564
    technique_name: Hide Artifacts
    evidence: The $INDEX_ALLOCATION stream can be used as a technique to prevent access to folders or files from tooling such as explorer.exe or powershell.exe.
    confidence_band: high
rules:
  - title: Detect Potential NTFS INDEX_ALLOCATION Hidden Directory Creation
    description: Detects the use of the ::$index_allocation stream in command lines, which is used to create hidden directories inaccessible to standard Windows tooling.
    platform: sigma
    severity: medium
    tactics:
      - stealth
    techniques:
      - T1564.004
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy the NTFS INDEX_ALLOCATION detection rule to production SIEM.
      owner: Detection Engineering
      due: 72h
      evidence: Source provides actionable Sigma rule for visibility.
  hunt_leads:
    - lead: Search endpoint logs for any command line processes containing '::$index_allocation'.
      technique_id: T1564.004
      data_needed:
        - Process creation events / command line history
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: The technique is specifically used for hidden file staging.
  mitigation_plan:
    - priority: medium
      action: Implement strict file system monitoring on sensitive directories for unexpected Alternate Data Stream (ADS) usage.
      owner: IT Operations
      addresses: T1564.004
      evidence: This technique bypasses file system standard tools.
  gaps:
    - Limited visibility into stream manipulation via API calls that do not involve the command line.
---

This technique involves the abuse of the NTFS filesystem structure, specifically the $INDEX_ALLOCATION attribute. By appending the string "::$INDEX_ALLOCATION" to a directory name during creation, an attacker can create a folder structure that standard Windows APIs and common management tools (such as Windows Explorer or PowerShell) struggle to traverse or list. This effectively hides the directory and its contents from the average user and administrative tools, providing a method for stealthy persistence or data staging. While the data remains accessible via low-level file system calls or specific command-line utilities, this technique is frequently leveraged to bypass automated monitoring and user discovery during the post-exploitation phase. Defenders should be aware that standard EDR process-creation logs may not always capture the full command-line arguments involving alternate data streams, depending on the specific sensor implementation and visibility.

## Impact

Successful implementation of this technique results in the creation of hidden directories that effectively bypass traditional file discovery methods. This allows an attacker to conceal malware payloads, exfiltrated data, or persistence mechanisms on an endpoint, reducing the likelihood of detection by security personnel and automated administrative cleanup tasks.

## Recommendation

- Deploy the provided Sigma rule to detect the use of "::$index_allocation" in command-line arguments.
- Verify your EDR/telemetry coverage, as many standard Sysmon configurations do not log alternate data stream path components in process-creation events.
- Prioritize auditing file system modifications for directories containing "::$index_allocation" strings.
