---
title: Awfulshred Malware Linux System Reboot Technique
slug: 2026-10-linux-sysrq-reboot
description: The Awfulshred wiper malware exploits the Linux System Request (SysRq) mechanism to force an immediate system reboot by writing to the proc/sysrq-trigger interface.
date: "2026-10-12T17:51:54Z"
type: threat
types:
  - threat
severities:
  - medium
actors:
  - Awfulshred
tags:
  - impact
  - malware
  - linux
  - data-destruction
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1529
    technique_name: System Shutdown/Reboot
    evidence: The following analytic detects the execution of the SysReq hack to reboot a Linux system host.
    confidence_band: high
rules:
  - title: Detect Linux System Reboot via SysRq Trigger
    description: Detects processes invoking the SysRq hack to reboot a Linux system by piping 'b' to /proc/sysrq-trigger
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1529
    data_sources:
      - process_creation
      - linux
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma rule to detect system reboot commands targeting /proc/sysrq-trigger
      owner: Detection Engineering
      due: 24h
      evidence: Source provides specific command pattern for detection
  hunt_leads:
    - lead: Search historic process creation logs for 'echo b > /proc/sysrq-trigger'
      technique_id: T1529
      data_needed:
        - Process creation logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: This is a high-fidelity indicator of malicious intent
---

The Awfulshred wiper malware employs an unconventional method to disrupt system operations by forcing an immediate, ungraceful reboot of a compromised Linux host. This technique leverages the Linux System Request (SysRq) feature, a kernel-level debugging tool, to trigger a hardware-level reboot without invoking standard shutdown sequences. By piping the character 'b' into the /proc/sysrq-trigger file, an attacker can bypass standard system management services, effectively causing immediate service denial and potentially hindering forensic preservation. This method is indicative of malicious activity, specifically observed in destructive wiper campaigns where the objective is to crash systems as part of a data destruction or anti-forensics lifecycle. Defenders should monitor for shell processes executing this specific command, as it is rarely utilized for legitimate system administration.

## Attack Chain

1. Initial access is established via exploitation or credential compromise.
2. The threat actor achieves persistent or elevated access on the Linux target.
3. The malware or attacker prepares the destructive payload or executes commands to facilitate disruption.
4. The attacker locates the kernel interface at /proc/sysrq-trigger.
5. The actor invokes a shell process such as bash, dash, or sudo to execute the command.
6. The command "echo b > /proc/sysrq-trigger" is executed, triggering the kernel immediate reboot function.
7. The system loses all unsaved data and services are forcibly terminated.
8. Final objective is achieved: system unavailability and potential obstruction of incident response efforts.

## Impact

The use of the SysRq reboot technique causes immediate system service disruption and potential data loss on affected Linux hosts. Observed in destructive campaigns like Awfulshred, this activity is intended to sabotage critical infrastructure, deny access to data, and complicate the incident response process by forcing a hard reboot during malicious operations.

## Recommendation

Prioritize monitoring of shell processes that interact with the /proc/sysrq-trigger kernel interface. 
- Deploy the provided Sigma rule to detect attempts to trigger system reboots via the SysRq interface.
- Audit current system and shell permissions to restrict which accounts or processes can modify files within /proc/sysrq-trigger.
- Implement EDR process-creation telemetry to capture command-line arguments involving system trigger files.
