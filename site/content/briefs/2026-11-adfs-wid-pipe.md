---
brief_id: brief-2026-11-25-adfs-wid-pipe
event_id: brief-2026-11-25-adfs-wid-pipe
revision: 1
activity_at: "2026-11-25T16:26:08Z"
title: Unauthorized Access to ADFS Configuration Database via Named Pipes
slug: 2026-11-adfs-wid-pipe
description: Suspicious local processes connecting to the Active Directory Federation Services (ADFS) Windows Internal Database (WID) named pipe may indicate an attempt to exfiltrate sensitive token-signing configuration data.
date: "2026-11-25T16:26:08Z"
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
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Detection logic sourced directly from established Sigma rule and validated against common environment exclusions.
tags:
  - collection
  - windows
  - adfs
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: Used to access information such as the AD FS configuration settings which contains sensitive information used to sign SAML tokens.
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/pipe_created/pipe_created_adfs_namedpipe_connection_uncommon_tool.yml
  - https://aadinternals.com/post/adfs/
  - https://github.com/Azure/Azure-Sentinel/blob/f99542b94afe0ad2f19a82cc08262e7ac8e1428e/Detections/SecurityEvent/ADFSDBNamedPipeConnection.yaml
rules:
  - title: Detect ADFS WID Named Pipe Access by Uncommon Process
    description: Detects local connections via named pipe to the Windows Internal Database (WID) used by ADFS, which may indicate unauthorized access to ADFS configuration settings.
    platform: sigma
    severity: medium
    tactics:
      - collection
    techniques:
      - T1005
    data_sources:
      - pipe_created
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Ensure Sysmon Event ID 17 and 18 are enabled on ADFS servers to capture named pipe activity.
      owner: IT Operations
      due: 48h
    - action: Deploy and tune the provided Sigma rule for ADFS WID pipe access.
      owner: Detection Engineering
      due: 24h
---

## Overview

Access to the ADFS configuration database, stored in the Windows Internal Database (WID), allows an attacker to extract sensitive information, including token-signing certificates used for SAML token creation. Accessing the WID instance via the named pipe '\MICROSOFT##WID\tsql\query' by unauthorized processes is a known technique for collecting ADFS configuration data. Defenders should monitor for connections to this specific pipe originating from processes other than legitimate ADFS service components, SQL management tools, or known identity health monitoring agents.

## Recommendation

- Deploy Sysmon (Event ID 17/18) to monitor named pipe connections.
- Implement the provided detection rule to identify uncommon processes accessing the WID named pipe.
- Audit legitimate administrative tools and service accounts in the environment to tune the exclusion list, ensuring critical infrastructure components are not flagged.
