---
brief_id: brief-2026-11-10-node-adobe-abuse
event_id: brief-2026-11-10-node-adobe-abuse
revision: 1
activity_at: "2026-11-10T03:02:37Z"
title: 'Adobe Creative Cloud: Execution of scripts via bundled node.exe'
slug: 2026-11-node-adobe-abuse
description: The node.exe binary bundled with Adobe Creative Cloud can be used to execute scripts. A detection rule is available to identify instances where node.exe executes files located outside of the Adobe Creative Cloud Experience JavaScript directory.
date: "2026-11-10T03:02:37Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
tags:
  - attack.execution
  - attack.stealth
  - attack.t1127
  - attack.t1059.007
references:
  - https://web.archive.org/web/20220406203641/https://twitter.com/mttaggart/status/1511804863293784064
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_node_adobe_creative_cloud_abuse.yml
rules:
  - title: Node Process Executions
    platform: sigma
    severity: medium
    data_sources:
      - process_creation
      - windows
rules_count: 1
---

Adobe Creative Cloud installations include a bundled node.exe binary. This binary can be used to execute scripts. 

## Detection
The following Sigma rule detects the execution of scripts by the Adobe Creative Cloud bundled node.exe when the script path is not located within the Adobe Creative Cloud Experience JavaScript resource directory.
