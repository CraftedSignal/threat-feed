---
title: DCRat Forkbomb Payload Activity
slug: 2026-10-dcrat-forkbomb
description: The DCRat malware utilizes a forkbomb technique, spawning rapid, high-volume processes of cmd.exe and notepad.exe to induce system instability and resource exhaustion.
date: "2026-10-09T12:15:21Z"
type: advisory
types:
  - advisory
severities:
  - medium
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The following analytic detects the execution of a DCRat 'forkbomb' payload, which spawns multiple cmd.exe processes.
    confidence_band: high
references:
  - https://cert.gov.ua/article/405538
  - https://malpedia.caad.fkie.fraunhofer.de/details/win.dcrat
  - https://www.mandiant.com/resources/analyzing-dark-crystal-rat-backdoor
rules:
  - title: Detect DCRat Forkbomb Process Activity
    description: Detects the rapid creation of cmd.exe processes spawning notepad.exe, which is indicative of a DCRat forkbomb payload.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.003
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
    - action: Deploy Sigma rule and enable threshold-based alerting for cmd.exe/notepad.exe forkbombs
      owner: Detection Engineering
      due: 24h
      evidence: DCRat forkbomb technique observed in EDR telemetry
  hunt_leads:
    - lead: Search for high-frequency process launches of notepad.exe spawned by cmd.exe
      technique_id: T1059.003
      data_needed:
        - Sysmon Event ID 1 logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source explicitly identifies the forkbomb behavior as high-frequency process spawning
---

DCRat, a known Remote Access Trojan (RAT), employs a destructive 'forkbomb' payload mechanism designed to compromise system stability. The threat actor leverages this technique to spawn a rapid succession of cmd.exe instances, which in turn launch numerous notepad.exe processes. This activity creates severe resource exhaustion, leading to potential denial of service or total system disruption. The behavior is typically initiated by a batch script execution. Defenders should monitor for high-frequency process creation patterns within a short time window (30 seconds) to identify potential DCRat infections in the environment. This technique is observed as part of the malware's post-exploitation capability to destabilize the target host.

## Attack Chain

1. Malware or an initial loader drops a malicious batch file onto the target Windows host.
2. The batch file is executed via a command shell, creating a parent cmd.exe process.
3. The batch script logic triggers an iterative loop to spawn multiple child processes.
4. Each iteration of the loop invokes a new cmd.exe instance.
5. Each cmd.exe instance launches an instance of notepad.exe.
6. The rapid, concurrent creation of 10 or more process pairs (cmd.exe -> notepad.exe) consumes system CPU and memory resources.
7. The system reaches a state of instability or performance degradation due to the forkbomb effect.

## Impact

Successful execution of this forkbomb payload leads to significant resource exhaustion, rendering the affected system unresponsive or unstable. This technique effectively disrupts legitimate services and can be used to prevent administrative access or security tool intervention during an ongoing intrusion, impacting productivity and system availability.

## Recommendation

* Deploy the Sigma rule below to detect rapid process creation patterns indicative of a forkbomb.
* Enable Sysmon Event ID 1 (Process Creation) logging across all endpoints to capture process lineage and command-line arguments.
* Configure EDR telemetry to ingest full process metadata, including process GUID and parent-child relationships, to facilitate the detection of rapid process spawning.
* Prioritize investigation of alerts identifying 10 or more cmd.exe to notepad.exe process pairs within a 30-second interval.
