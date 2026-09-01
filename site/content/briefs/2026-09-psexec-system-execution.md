---
title: Detection of PsExec Service Execution as SYSTEM
slug: 2026-09-psexec-system-execution
description: Detection of unauthorized remote command execution via PSEXESVC where child processes are spawned with SYSTEM-level privileges.
date: "2026-09-01T12:27:13Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - lateral-movement
  - execution
  - sysinternals
  - windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1569
    technique_name: System Services
    evidence: Detects suspicious launch of the PSEXESVC service on this system and a sub process run as LOCAL_SYSTEM (-s).
    confidence_band: high
rules:
  - title: Detect PSEXESVC Child Process Execution as LOCAL SYSTEM
    description: Detects suspicious launch of the PSEXESVC service child process run as LOCAL SYSTEM, indicating remote execution with highest privileges.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1569.002
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma detection rule to SIEM and monitor for hits
      owner: Detection Engineering
      due: 48h
      evidence: Sigma rule provided in brief
  hunt_leads:
    - lead: Search logs for any execution of PSEXESVC.exe across the fleet
      technique_id: T1569.002
      data_needed:
        - Process creation events
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: PsExec is a common tool for lateral movement and its presence should be investigated
  mitigation_plan:
    - priority: medium_term
      action: Restrict PSEXESVC.exe usage via AppLocker or EDR block rules
      owner: IT Operations
      addresses: Lateral movement and privilege escalation risk
      evidence: General security best practices for administrative tools
---

The Sysinternals PsExec utility is frequently leveraged by threat actors to perform remote command execution and lateral movement. When the utility is used with the -s flag, the associated service, PSEXESVC.exe, executes remote commands with LOCAL SYSTEM privileges rather than those of the authenticated user. While PsExec is a legitimate administration tool, its execution by non-authorized accounts often indicates an ongoing attack where an adversary has already obtained administrative credentials and is escalating to system-level access to disable security software, dump credentials, or establish persistence. Monitoring for child processes of PSEXESVC.exe executing under the SYSTEM user account is a high-fidelity indicator of such activity.

## Attack Chain

1. Attacker performs credential dumping on an initial entry point to obtain local administrator credentials.
2. Attacker uses PsExec to authenticate to a target endpoint using stolen credentials via SMB/RPC.
3. The PSEXESVC service binary is dropped into the Admin$ share on the remote target.
4. The service is started remotely using the Service Control Manager.
5. The PSEXESVC.exe process initializes and creates a process designated by the attacker.
6. The child process runs as LOCAL SYSTEM due to the -s flag provided by the attacker.
7. Attacker executes malicious payloads, such as backdoors or ransomware components, with elevated privileges.
8. Attacker clears logs or modifies system configurations to maintain stealth.

## Impact

Successful abuse of PsExec to gain SYSTEM privileges typically leads to full host compromise, including the ability to disable EDR/AV solutions, exfiltrate sensitive data, and perform domain-wide movement. This technique is observed in widespread ransomware deployments and targeted espionage campaigns where administrative lateral movement is a core objective.

## Recommendation

* Deploy the provided Sigma rule to monitor for suspicious process creation events originating from PSEXESVC.exe.
* Enable Sysmon process-creation logging to capture the ParentImage and User fields.
* Audit and restrict the use of PsExec across the environment, limiting execution to authorized jump hosts or administrative management workstations.
* Tune the detection to account for legitimate IT management tooling, such as the Microsoft Intune management extension, which may trigger similar alerts.
