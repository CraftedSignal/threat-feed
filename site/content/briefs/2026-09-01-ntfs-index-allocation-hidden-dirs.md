---
brief_id: brief-2026-09-01-ntfs-index-allocation-hidden-dirs
event_id: brief-2026-09-01-ntfs-index-allocation-hidden-dirs
revision: 2
activity_at: "2026-11-25T16:34:57Z"
revision_history:
  - revision: 2
    at: "2026-11-25T16:34:57Z"
    checksum: sha256:0ca009a317decde9d283a44cd21787640e9baec2f30921ab74bfea70cf632198
    summary: OS windows
    changed_fields:
      - affected_os
      - affected_products
      - affected_vendors
      - lastmod
      - references
      - rules
      - ttps
      - updates
    source_urls:
      - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_susp_hidden_dir_index_allocation.yml
title: Abuse of NTFS INDEX_ALLOCATION Stream for Directory Obfuscation
slug: 2026-09-01-ntfs-index-allocation-hidden-dirs
description: Attackers can abuse the NTFS $INDEX_ALLOCATION stream to create directories that are inaccessible to standard Windows utilities like Explorer and PowerShell, facilitating stealthy data storage.
date: "2026-09-01T12:25:07Z"
lastmod: "2026-11-25T16:32:27Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Rule defined based on community-verified Sigma patterns.
tags:
  - stealth
  - persistence
  - windows
  - ntfs
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1564
    technique_name: Hide Artifacts
    subtechnique_id: T1564.004
    subtechnique_name: NTFS File Attributes
    evidence: The $INDEX_ALLOCATION stream can be used as a technique to prevent access to folders or files from tooling such as explorer.exe or powershell.exe.
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_susp_hidden_dir_index_allocation.yml
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
updates:
  - at: "2026-11-25T16:32:27Z"
    level: L1
    summary: OS windows
    sources:
      - sigma-hq
    source_urls:
      - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_susp_hidden_dir_index_allocation.yml
---

## Overview

This technique involves the abuse of the NTFS filesystem structure, specifically the $INDEX_ALLOCATION attribute. By appending the string "::$INDEX_ALLOCATION" to a directory name during creation, an attacker can create a folder structure that standard Windows APIs and common management tools (such as Windows Explorer or PowerShell) struggle to traverse or list. This effectively hides the directory and its contents from the average user and administrative tools, providing a method for stealthy persistence or data staging. While the data remains accessible via low-level file system calls or specific command-line utilities, this technique is frequently leveraged to bypass automated monitoring and user discovery during the post-exploitation phase. Defenders should be aware that standard EDR process-creation logs may not always capture the full command-line arguments involving alternate data streams, depending on the specific sensor implementation and visibility.

## Impact

Successful implementation of this technique results in the creation of hidden directories that effectively bypass traditional file discovery methods. This allows an attacker to conceal malware payloads, exfiltrated data, or persistence mechanisms on an endpoint, reducing the likelihood of detection by security personnel and automated administrative cleanup tasks.

## Recommendation

- Deploy the provided Sigma rule to detect the use of "::$index_allocation" in command-line arguments.
- Verify your EDR/telemetry coverage, as many standard Sysmon configurations do not log alternate data stream path components in process-creation events.
- Prioritize auditing file system modifications for directories containing "::$index_allocation" strings.
