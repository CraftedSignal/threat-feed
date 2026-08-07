---
title: Detection of Linux Persistence via Systemd Generators
slug: 2026-08-linux-systemd-generator-persistence
description: This detection identifies potential persistence on Linux systems by monitoring for unauthorized file creation or modification within the /lib/systemd/system-generators/ directory, which executes during the boot sequence.
date: "2026-08-07T15:15:27Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - linux
  - systemd
products:
  - systemd
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1037.005
    technique_name: 'Boot or Logon Initialization Scripts: Systemd Generators'
    evidence: The following analytic detects potential persistence using a systemd generator on Linux, which involves creating a malicious script or binary that is typically executed during the system's boot process.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: Systemd generators are typically placed in directories like /lib/systemd/system-generators/, where they are run early in the boot sequence to dynamically generate or modify unit files that control system services.
    confidence_band: high
rules:
  - title: Detect File Creation in Systemd Generator Directory
    description: Detects file creation or modification in the systemd generator directory, a technique often used for Linux persistence.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1037.005
      - T1547
    data_sources:
      - file_event
      - linux
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy file monitoring rule for systemd-generators directory.
      owner: Detection Engineering
      due: 48h
      evidence: Source detection logic.
  hunt_leads:
    - lead: Identify all existing files in /lib/systemd/system-generators/ not belonging to a known package manager (e.g., dpkg -S).
      technique_id: T1037.005
      data_needed:
        - File list from /lib/systemd/system-generators/
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Persistence technique documentation.
---

Attackers may establish persistence on Linux systems by creating or modifying files within the /lib/systemd/system-generators/ directory. Systemd generators are specialized executables run by the systemd manager early in the system boot sequence to dynamically generate unit files for service orchestration. By placing a custom script or binary in this directory, an adversary ensures that their payload is executed with high privileges every time the system starts. This technique allows for stealthy persistence that survives standard reboots and provides a mechanism to manipulate the system state before other security services may be fully initialized. Monitoring this directory is critical for detecting unauthorized configuration changes and potential lateral movement or backdoor deployment.

## Impact

Successful exploitation allows an adversary to maintain long-term, high-privileged access to compromised Linux hosts. This can lead to full system compromise, data exfiltration, or the deployment of additional malicious modules that survive typical incident response remediation steps like service restarts, necessitating deep forensic analysis of the boot process to eradicate the threat.

## Recommendation

- Deploy the provided Sigma rule to detect file modifications in systemd generator directories using Sysmon for Linux telemetry.
- Establish a baseline of known-good systemd generator files and alert on any new file creation in /lib/systemd/system-generators/ not associated with official package management activity (e.g., apt, yum, dnf).
- Enable Sysmon for Linux File Event logging (Event ID 11) specifically targeting critical system configuration paths.
- Integrate these detections into the SOC's incident response workflow to trigger immediate investigation of the user context and parent process responsible for the file modification.
