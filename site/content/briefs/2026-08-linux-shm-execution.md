---
title: Detection of Linux Binary Execution from Shared Memory Directories
slug: 2026-08-linux-shm-execution
description: Detection of root-level execution of binaries from volatile shared memory directories (/dev/shm/ and /run/shm/) used by threat actors for fileless persistence and forensic evasion.
date: "2026-08-07T15:15:19Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - linux
  - post-exploitation
  - persistence
  - tmpfs
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The analytic identifies the execution of a binary by root from Linux shared memory directories.
    confidence_band: high
rules:
  - title: Detect Linux Binary Execution from Shared Memory
    description: Detects the execution of binaries by root from Linux shared memory directories /dev/shm/ and /run/shm/
    platform: sigma
    severity: medium
    tactics:
      - execution
      - persistence
      - privilege-escalation
    techniques:
      - T1059
    data_sources:
      - process_creation
      - linux
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma detection rule to SIEM
      owner: Detection Engineering
      due: 48h
      evidence: Source provides analytic logic for identifying execution from SHM
  hunt_leads:
    - lead: Identify all processes running from /dev/shm or /run/shm
      technique_id: T1059
      data_needed:
        - Process creation events (Sysmon EID 1)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Shared memory directories are non-persistent and rare for standard binaries
  mitigation_plan:
    - priority: medium_term
      action: Review and restrict write/execute permissions on /dev/shm and /run/shm for non-essential users
      owner: IT Operations
      addresses: Persistence and staging
      evidence: Hardening reduces the attack surface for fileless malware
---

Security analysts have identified an increase in threat actors utilizing Linux shared memory directories, specifically /dev/shm/ and /run/shm/, to execute malicious binaries. These directories are backed by tmpfs, meaning they exist entirely in virtual memory and lack persistent storage on the physical disk. By staging and executing malware from these locations, attackers can maintain a footprint on high-uptime servers while effectively bypassing traditional disk-based forensic investigations. This activity is particularly concerning when performed by the root user, as it often signals the establishment of system backdoors or the final stages of privilege escalation. Monitoring for execution from these paths is a critical component of identifying stealthy post-exploitation activity on Linux endpoints.

## Impact

Successful exploitation allows threat actors to maintain persistent, fileless backdoors on Linux infrastructure. Because these files do not persist on disk, detecting them requires real-time monitoring of process execution telemetry. Failure to detect this activity can lead to long-term unauthorized access, data exfiltration, and lateral movement within the environment without leaving traditional file-system artifacts for incident responders to analyze.

## Recommendation

* Deploy the Sigma rules provided in this brief to monitor for process execution originating from /dev/shm/ and /run/shm/ by the root user.
* Enable Sysmon for Linux (EventID 1) or equivalent EDR telemetry to capture process path and command-line execution data.
* Configure SIEM alerts to filter out legitimate applications that utilize these directories for transient inter-process communication; establish a baseline of known-good software behavior to minimize false positives.
* Incorporate these detection points into incident response playbooks for Linux post-exploitation and privilege escalation hunts.
