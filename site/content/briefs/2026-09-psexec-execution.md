---
title: Detection of PsExec Execution
slug: 2026-09-psexec-execution
description: This brief documents the detection logic for identifying the use of the Sysinternals PsExec utility, a common tool for lateral movement and remote code execution.
date: "2026-09-01T12:27:05Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - lateral-movement
  - sysinternals
  - windows
  - execution
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1569
    technique_name: System Services
    evidence: The utility is used to execute processes on remote systems, which is mapped to lateral movement and execution techniques.
    confidence_band: high
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
    evidence: PsExec is a hallmark tool for remote service manipulation and lateral movement.
    confidence_band: high
references:
  - https://www.fireeye.com/blog/threat-research/2020/10/kegtap-and-singlemalt-with-a-ransomware-chaser.html
rules:
  - title: Detect PsExec Execution
    description: Detects the execution of the Sysinternals PsExec utility by matching the process image name or its original file name metadata.
    platform: sigma
    severity: medium
    tactics:
      - execution
      - lateral-movement
    techniques:
      - T1021
      - T1569
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma detection rule to production SIEM.
      owner: Detection Engineering
      due: 48h
      evidence: Source provides specific detection criteria for PsExec.
  mitigation_plan:
    - priority: medium_term
      action: Restrict PsExec usage to specific administrative subnets or jump hosts.
      owner: IT Operations
      addresses: Lateral Movement TTPs
---

PsExec is a legitimate administration tool from the Windows Sysinternals suite frequently abused by threat actors to facilitate lateral movement and remote code execution. Attackers leverage PsExec to execute processes on remote systems using administrative credentials, bypassing standard authentication hurdles. Because PsExec requires an initial acceptance of an End User License Agreement (EULA) upon first run on a system, threat actors often include the -accepteula flag in their command-line arguments to ensure automated, non-interactive execution. Defenders should monitor for the invocation of PsExec to identify unauthorized administrative activity and potential lateral movement across the network.

## Impact

Successful unauthorized use of PsExec allows attackers to pivot within an environment, execute arbitrary commands with SYSTEM privileges, deploy malware, or establish persistence. Its use is associated with various ransomware operations and state-sponsored espionage campaigns where lateral movement is a core objective.

## Recommendation

Deploy the provided Sigma rule to identify PsExec execution. Prioritize investigating command lines involving the -accepteula flag. Establish a process to inventory legitimate administrative use of PsExec and add these specific workstations or service accounts to a monitor-only allowlist to reduce noise. Enable Sysmon or Windows Event Log ID 4688 to capture the required process creation telemetry.
