---
brief_id: brief-2026-11-10-defaultpack-child-process
event_id: brief-2026-11-10-defaultpack-child-process
revision: 1
activity_at: "2026-11-10T02:36:18Z"
title: DefaultPack.exe process execution monitoring
slug: 2026-11-defaultpack-child-process
description: DefaultPack.exe is a legitimate Windows binary that can be abused as a LOLBAS proxy to execute arbitrary child processes.
date: "2026-11-10T02:36:18Z"
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
qa_status:
  verdict: pass
tags:
  - living-off-the-land
  - execution
  - lolbas
  - process-monitoring
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1218
    technique_name: System Binary Proxy Execution
    evidence: DefaultPack.exe is documented in the LOLBAS project as a binary capable of proxying other programs.
    confidence_band: high
references:
  - https://lolbas-project.github.io/lolbas/OtherMSBinaries/DefaultPack/
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_defaultpack_uncommon_child_process.yml
rules:
  - title: Detect DefaultPack.exe Child Process
    description: Detects the execution of any child process spawned by DefaultPack.exe
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1218
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: monitor_or_close
  owners:
    - Detection Engineering
  hunt_leads:
    - lead: Baseline all child processes spawned by DefaultPack.exe to identify legitimate usage.
      technique_id: T1218
      data_needed:
        - Process creation logs (ParentImage and Image fields)
      priority: low
      confidence: medium
      disposition: convert_to_detection
      evidence: DefaultPack.exe is a known LOLBAS binary, making it a target for proxy execution.
---

DefaultPack.exe is a legitimate Windows component that can be leveraged by attackers to proxy the execution of other binaries. Monitoring for child processes spawned by this executable is an effective way to identify potential living-off-the-land (LotL) execution attempts.

## Recommendation

Deploy the provided Sigma rule to detect and audit child processes spawned by DefaultPack.exe. Given the lack of a known baseline for legitimate child processes in all environments, monitor this activity to establish an allowlist of permitted execution paths before moving to blocking mode.
