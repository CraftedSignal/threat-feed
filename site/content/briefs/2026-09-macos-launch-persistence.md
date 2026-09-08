---
title: Detection of Unauthorized macOS Launch Service Persistence
slug: 2026-09-macos-launch-persistence
description: Adversaries achieve persistence on macOS by creating or modifying launch agent or daemon plist files and immediately loading them into the launchd subsystem using the launchctl utility.
date: "2026-09-08T13:32:34Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - persistence
  - execution
  - macos
affected_os:
  - macOS
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1543
    technique_name: Create or Modify System Process
    evidence: An adversary can establish persistence by installing a new launch agent that executes at login by using launchd or launchctl to load a plist into the appropriate directories.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1569
    technique_name: System Services
    evidence: The detection rule identifies such activities by monitoring file changes in Launch Agent directories and subsequent immediate loading via launchctl.
    confidence_band: high
references:
  - https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html
rules:
  - title: Detect macOS Launch Service Creation and Immediate Loading
    description: Detects the creation or modification of a launch agent or daemon plist file followed by the immediate execution of launchctl to load the service.
    platform: sigma
    severity: low
    tactics:
      - persistence
    techniques:
      - T1543.001
      - T1543.004
      - T1569.001
    data_sources:
      - process_creation
      - macos
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Deploy the Sigma detection rule to the SIEM and calibrate against known software install paths.
      owner: Detection Engineering
      due: 48h
      evidence: Source provided logic for detecting persistence via launch services.
  hunt_leads:
    - lead: Identify all currently running services launched via launchctl from user-writable directories.
      technique_id: T1543.001
      data_needed:
        - Process tree logs
        - Filesystem integrity logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Standard attacker persistence technique on macOS.
  mitigation_plan:
    - priority: medium
      action: Implement strict file integrity monitoring (FIM) on /Library/LaunchAgents and /Library/LaunchDaemons.
      owner: IT Operations
      addresses: T1543
      evidence: Hardening baseline for macOS endpoint security.
---

Adversaries targeting macOS systems often seek to establish persistence to ensure their malicious payloads survive system reboots or user logouts. A primary method for achieving this is through the abuse of macOS launch services, specifically by creating or modifying property list (plist) files within designated LaunchAgent or LaunchDaemon directories. By placing a configuration file in these locations, an attacker defines a service that the operating system's launchd subsystem will execute automatically. To finalize this process, attackers typically use the `launchctl` utility to manually load or bootstrap the newly created service into the system configuration. This sequence of file creation followed by immediate service activation is a strong indicator of persistence establishment and should be closely monitored by security teams to detect unauthorized background execution.

## Attack Chain

1. Attacker gains initial access or code execution on the macOS endpoint.
2. Attacker prepares a malicious payload (script or binary) to be executed.
3. Attacker creates or modifies a plist configuration file defining the service.
4. Attacker writes the plist file to a persistence directory (e.g., /Library/LaunchAgents/).
5. Attacker executes `launchctl` with the `load` or `bootstrap` argument.
6. The `launchd` process processes the request and registers the new service.
7. The malicious service is now configured to run automatically upon system start or login.
8. Final objective: persistence for recurring malicious activity or exfiltration.

## Impact

Successful exploitation allows attackers to maintain long-term, stealthy control over the compromised macOS host. This permits continuous exfiltration of data, recurring monitoring of user activity, or periodic command-and-control communication, significantly increasing the difficulty of incident remediation and eradication.

## Recommendation

Prioritize the identification of unauthorized modifications to launch service directories and the subsequent invocation of `launchctl`.
- Deploy the Sigma rule provided below to identify sequences of plist creation followed by `launchctl` service loading.
- Review all current LaunchAgent and LaunchDaemon plists in `/System/Library/`, `/Library/`, and `/Users/*/Library/` for suspicious executables.
- Establish a baseline of legitimate software that requires launch service persistence to reduce false positives during incident response.
