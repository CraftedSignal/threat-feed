---
title: Braodo Stealer Screen Capture Activity
slug: 2026-08-braodo-stealer-screen-capture
description: The Braodo stealer malware captures victim desktop screenshots and stages them in temporary directories, facilitating subsequent data exfiltration.
date: "2026-08-19T22:29:17Z"
type: threat
types:
  - threat
severities:
  - medium
actors:
  - Braodo Stealer
tags:
  - stealer
  - information-theft
  - windows
  - collection
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1113
    technique_name: Screen Capture
    evidence: The Braodo stealer is known to capture screenshots of the victim's desktop as part of its data theft activities.
    confidence_band: high
references:
  - https://x.com/suyog41/status/1825869470323056748
  - https://g0njxa.medium.com/from-vietnam-to-united-states-malware-fraud-and-dropshipping-98b7a7b2c36d
rules:
  - title: Detect Braodo Stealer Screen Capture in Temp Folder
    description: Detects the creation of common screenshot file names in temporary folders, a technique used by Braodo and other stealers to stage captured data.
    platform: sigma
    severity: medium
    tactics:
      - collection
    techniques:
      - T1113
    data_sources:
      - file_event
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the provided Sigma rule to production SIEM.
      owner: Detection Engineering
      due: 48h
      evidence: Source provides specific file names and paths for the malicious activity.
  hunt_leads:
    - lead: Search for existing file creation events matching common screenshot filenames in temp paths over the past 30 days.
      technique_id: T1113
      data_needed:
        - Sysmon Event ID 11
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Malware behavior is well-documented in threat intel reports.
---

Braodo stealer is a malicious software strain documented to perform unauthorized desktop screen captures. The malware targets Windows endpoints to record user activity, saving the output in image formats including .png, .jpg, and .bmp. These files are systematically written to directories containing the 'temp' string to blend in with legitimate system and application transient files before being staged for exfiltration. This behavior is indicative of an information-stealing operation, where captured imagery provides the adversary with sensitive visual data, such as credentials, system configuration, or personal information displayed on the desktop. The activity has been observed in various campaigns, including those linked to the StealC and Vidar stealers, as well as the Hellcat ransomware, emphasizing its role as a common component of modern multi-stage cyberattacks.

## Attack Chain

1. Initial access is established on the Windows endpoint via secondary malicious payload delivery.
2. The malware executes and identifies system process environments to ensure persistence and privilege requirements.
3. The Braodo stealer component invokes Windows API calls to capture the desktop image.
4. The captured screen image is encoded and temporarily held in system memory.
5. The malware writes the screen capture to the filesystem using fixed names like screenshot.png or screenshot.jpg.
6. The file is saved within a user or system temporary folder (e.g., C:\Users\&lt;user>\AppData\Local\Temp\) to minimize detection.
7. The malware verifies the successful write operation to the temporary directory.
8. The captured image is exfiltrated to an attacker-controlled command and control server.

## Impact

The primary impact of this activity is the unauthorized acquisition of sensitive visual data from the compromised endpoint. By capturing the screen, attackers gain insight into active applications, open browser sessions, and potentially sensitive documents, which can lead to identity theft, financial fraud, or further lateral movement within a compromised network.

## Recommendation

Deploy detection for file creation events involving common screen capture filenames in temporary directories to identify potential infostealer activity. Ensure that Sysmon Event ID 11 (FileCreate) is being collected across all Windows endpoints and forwarded to the SIEM. Integrate the provided Sigma rule to alert on suspicious file writing patterns in the temp directory.
