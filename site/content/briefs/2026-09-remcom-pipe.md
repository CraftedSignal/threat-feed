---
title: RemCom Administrative Tool Named Pipe Usage
slug: 2026-09-remcom-pipe
description: Detection of the default named pipe used by the RemCom remote administration tool, which is frequently leveraged by attackers for lateral movement and remote command execution.
date: "2026-09-01T12:18:28Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - lateral-movement
  - execution
  - remcom
  - sysmon
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
    evidence: Detects default RemCom pipe creation.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1569
    technique_name: System Services
    evidence: Detects default RemCom pipe creation.
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/pipe_created/pipe_created_pua_remcom_default_pipe.yml
  - https://github.com/kavika13/RemCom
rules:
  - title: Detect RemCom Default Named Pipe Creation
    description: Detects the creation of named pipes associated with the RemCom remote administration tool
    platform: sigma
    severity: medium
    tactics:
      - execution
      - lateral_movement
    techniques:
      - T1021.002
      - T1569.002
    data_sources:
      - pipe_created
      - windows
rules_count: 1
action_plan:
  priority: monitor_or_close
  owners:
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Deploy Sigma detection rule to SIEM
      owner: Detection Engineering
      due: 72h
      evidence: Source provides standard detection logic
  hunt_leads:
    - lead: Search for historical instances of '\RemCom' pipes in existing pipe creation telemetry
      technique_id: T1021.002
      data_needed:
        - Sysmon Event ID 17
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Pipe names are static artifacts of the RemCom tool
---

RemCom is a remote administration tool designed to function similarly to the Windows PsExec utility, allowing users to execute commands on remote systems. While used for legitimate administrative tasks, its default behavior includes the creation of specific named pipes, which makes it a persistent artifact for detection engineers. Threat actors often adopt RemCom for lateral movement or as a secondary payload execution mechanism due to its ability to facilitate remote service installation and interactive command shell access. Defenders should monitor for the creation of these pipes as a indicator of potential unauthorized remote access or administrative activity occurring within the environment.

## Impact

Successful deployment of RemCom within a target network enables attackers to move laterally, escalate privileges, and execute arbitrary code on remote hosts. This activity can lead to full system compromise, exfiltration of sensitive data, and widespread ransomware deployment if the tool is utilized by unauthorized actors.

## Recommendation

Deploy the provided Sigma rule to detect the creation of RemCom-specific named pipes. Ensure that Sysmon Event ID 17 (Pipe Created) is enabled in your environment's telemetry configuration to provide visibility into this activity. Investigate any instances where these pipes are created by processes originating from non-administrative service accounts or unconventional parent processes, as this may indicate an active security incident.
