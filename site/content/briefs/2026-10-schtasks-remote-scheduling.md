---
title: Detection of Remote Scheduled Task Creation via Schtasks
slug: 2026-10-schtasks-remote-scheduling
description: Adversaries utilize schtasks.exe with remote command-line arguments to establish persistence or facilitate lateral movement across Windows environments.
date: "2026-10-12T17:58:24Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - lateral-movement
  - persistence
  - living-off-the-land
  - windows
  - lotlbin
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1053
    technique_name: Scheduled Task/Job
    evidence: The following analytic detects the use of 'schtasks.exe' to create a scheduled task on a remote system.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
    evidence: This activity is significant as it may signify an adversary's attempt to persist or execute code remotely.
    confidence_band: high
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1053
    technique_name: Scheduled Task/Job
    evidence: The following analytic detects the use of 'schtasks.exe' to create a scheduled task on a remote system, indicating potential lateral movement.
    confidence_band: high
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/388942adbd9641f4dfdcf079d7efe9a75ec0ac43/atomics/T1053.005/T1053.005.yaml#L43
rules:
  - title: Detect Remote Scheduled Task Creation via Schtasks
    description: Detects the use of schtasks.exe with /create and /s flags indicating remote scheduled task creation
    platform: sigma
    severity: medium
    tactics:
      - execution
      - lateral_movement
      - persistence
    techniques:
      - T1053.005
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
    - action: Deploy the provided Sigma rule for monitoring schtasks.exe remote flags
      owner: Detection Engineering
      due: 48h
      evidence: Analytic requirement to identify remote task scheduling
  hunt_leads:
    - lead: Search historic process creation logs for schtasks.exe /s
      technique_id: T1053.005
      data_needed:
        - Process creation telemetry
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Adversaries use this for lateral movement
  mitigation_plan:
    - priority: medium_term
      action: Restrict remote management capabilities via Group Policy where not required
      owner: IT Operations
      addresses: T1053.005
      evidence: Reduces attack surface for lateral movement
---

The use of the Windows native utility 'schtasks.exe' to remotely create scheduled tasks is a frequent technique observed in lateral movement and persistence phases of an attack. By leveraging the '/create' and '/s' flags, an actor can execute commands or binaries on a remote target system without needing interactive access. This behavior is documented as a core component of several adversary campaigns, including the deployment of Prestige Ransomware, Phemedrone Stealer, and Quasar RAT, and has been observed in activity attributed to the NOBELIUM group. Because this technique relies on built-in living-off-the-land binaries (LotLBin), it is a high-utility method for attackers to maintain long-term access or move laterally within a compromised Active Directory environment. Defenders should monitor process-level telemetry for the invocation of schtasks.exe with flags indicative of remote targeting.

## Attack Chain

1. Attacker gains initial access to an endpoint within the target network.
2. Attacker performs credential harvesting or token theft to obtain administrative privileges.
3. Attacker identifies a secondary target host via internal network reconnaissance.
4. Attacker executes schtasks.exe with the '/s' parameter to specify the remote host name and the '/create' flag to define a new task.
5. The remote host schedules the attacker-defined task, often pointing to an obfuscated script or malicious binary.
6. The scheduled task executes, providing the attacker with remote code execution (RCE) on the target host.
7. Attacker achieves persistence or pivots further into the network from the newly compromised host.

## Impact

Successful exploitation allows attackers to gain unauthorized remote code execution, move laterally to sensitive systems, and establish persistent access. This technique has been observed across various sectors as part of multi-stage intrusions leading to ransomware deployment, data exfiltration, or long-term cyber espionage.

## Recommendation

Prioritize the implementation of process-creation monitoring to detect suspicious usage of native administrative tools.
* Deploy the Sigma rule below to your SIEM to monitor for schtasks.exe remote execution attempts.
* Enable Sysmon Event ID 1 or Windows Security Event ID 4688 to capture comprehensive command-line arguments for all processes.
* Review all administrative scheduled task creation alerts in the context of the user identity and the destination host to filter out legitimate automated management tasks.
