---
title: Detection of PsExec Service Execution Artefacts
slug: 2026-09-psexec-file-artefact
description: PsExec leaves a distinct file-system artifact on target systems during service execution that can be used to detect lateral movement.
date: "2026-09-01T12:17:46Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - lateral-movement
  - privilege-escalation
  - execution
  - persistence
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1570
    technique_name: Lateral Tool Transfer
    evidence: PsExec is a common tool used for lateral movement and remote execution.
    confidence_band: high
references:
  - https://aboutdfir.com/the-key-to-identify-psexec/
  - https://twitter.com/davisrichardg/status/1616518800584704028
rules:
  - title: Detect PsExec Service Execution Artefact
    description: Detects the creation of the PsExec service key file in C:\Windows\, which is generated during PsExec remote command execution.
    platform: sigma
    severity: high
    tactics:
      - execution
      - lateral-movement
      - persistence
      - privilege-escalation
    techniques:
      - T1136.002
      - T1543.003
      - T1570
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
    - action: Deploy Sigma detection rule to SIEM.
      owner: Detection Engineering
      due: 48h
      evidence: Source provides specific file naming conventions for PsExec artifacts.
  hunt_leads:
    - lead: Search historic file creation logs for PSEXEC-*.key patterns.
      technique_id: T1570
      data_needed:
        - File creation event logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: PsExec leaves traceable artifacts on the target file system.
---

PsExec is a popular administrative tool within the Sysinternals Suite, often leveraged by attackers for lateral movement, remote command execution, and privilege escalation. When PsExec is executed against a remote target, it installs a service on the target machine and creates a unique temporary file on the filesystem to facilitate the session. This file typically follows the naming convention 'PSEXEC-*.key' and is located in the 'C:\Windows\' directory. Detecting the creation of these specific files provides high-fidelity visibility into PsExec usage within an environment, enabling defenders to identify unauthorized remote administration or attacker movement between compromised hosts.

## Impact

The unauthorized use of PsExec can lead to remote code execution, credential dumping, and full system compromise. If an attacker gains access to credentials with administrative privileges, they can use this tool to move laterally through an environment, escalate privileges, and establish persistence, potentially affecting multiple systems across the network simultaneously.

## Recommendation

Detection engineering teams should monitor filesystem activity for the creation of PsExec service key files.

* Deploy the provided Sigma rule to monitor 'file_event' logs for the specific naming pattern 'C:\Windows\PSEXEC-*.key'.
* Configure host-based logging (such as Sysmon Event ID 11 or USN Journal monitoring) to capture file creation events.
* Use the detected file creation events to trigger an incident response investigation to verify if the execution of PsExec was authorized by system administrators.
