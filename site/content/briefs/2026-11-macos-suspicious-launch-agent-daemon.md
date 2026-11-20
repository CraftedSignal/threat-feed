---
brief_id: brief-2026-11-02-macos-suspicious-launch-agent-daemon
event_id: brief-2026-11-02-macos-suspicious-launch-agent-daemon
revision: 1
activity_at: "2026-11-02T09:09:21Z"
title: Persistence via Suspicious Launch Agent or Launch Daemon on macOS
slug: 2026-11-macos-suspicious-launch-agent-daemon
description: This detection rule identifies the creation of macOS Launch Agent or Launch Daemon property list (plist) files by suspicious processes, a technique used by malware such as RustBucket, Shlayer, and CloudMensis to establish persistence.
date: "2026-11-02T09:09:21Z"
lastmod: "2026-11-20T01:55:18Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: roughly even chance
tags:
  - macOS
  - Persistence
  - Defense Evasion
affected_os:
  - macOS
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: An adversary may establish persistence by installing a new launch agent or daemon which executes at login.
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1543
    technique_name: Create or Modify System Process
    subtechnique_id: T1543.001
    subtechnique_name: Launch Agent
    evidence: This detection rule identifies the creation of a launch agent or daemon property list file.
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1543
    technique_name: Create or Modify System Process
    subtechnique_id: T1543.004
    subtechnique_name: Launch Daemon
    evidence: This detection rule identifies the creation of a launch agent or daemon property list file.
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1647
    technique_name: Plist File Modification
    evidence: This detection rule identifies the creation of a launch agent or daemon property list file.
references:
  - https://medium.com/red-teaming-with-a-blue-team-mentality/a-brief-look-at-macos-detections-and-post-infection-analysis-b0ede7ecfeb9
  - https://objective-see.org/blog
  - https://www.elastic.co/security-labs/DPRK-strikes-using-a-new-variant-of-rustbucket
  - https://github.com/elastic/detection-rules/blob/main/rules/macos/persistence_suspicious_launch_agent_or_launch_daemon.toml
action_plan:
  hunt_leads:
    - lead: Identify plist creation events in standard persistence directories (LaunchAgents/LaunchDaemons) where the originating process is a scripting interpreter or executing from a high-risk directory such as /tmp, /var/tmp, or /private/var/folders.
      technique_id: T1547
      data_needed:
        - file.path
        - process.executable
        - process.name
        - event.type
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: An adversary may establish persistence by installing a new launch agent or daemon which executes at login.
    - lead: Search for newly created property list files in system/user library paths where the parent process lacks a trusted code signature or is an unauthorized interpreter, indicating unauthorized configuration of system processes.
      technique_id: T1543
      data_needed:
        - file.path
        - process.executable
        - process.code_signature.signing_id
        - process.code_signature.trusted
      priority: high
      confidence: medium
      disposition: convert_to_detection
      evidence: This detection rule identifies the creation of a launch agent or daemon property list file.
    - lead: Audit file write events specifically for .plist extensions within /Library/LaunchAgents/ or /Library/LaunchDaemons/ directories initiated by non-installer binaries to detect potential plist file modification/creation for persistence.
      technique_id: T1647
      data_needed:
        - file.path
        - file.extension
        - process.executable
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: This detection rule identifies the creation of a launch agent or daemon property list file.
updates:
  - at: "2026-11-20T01:55:18Z"
    level: L1
    summary: merged coverage from Persistence via Suspicious Launch Agent or Launch Daemon on macOS
    sources:
      - elastic
    source_urls:
      - https://github.com/elastic/detection-rules/blob/main/rules/macos/persistence_suspicious_launch_agent_or_launch_daemon.toml
---

## Overview
LaunchAgents and LaunchDaemons are the standard macOS mechanisms for starting programs automatically at user login or system boot. While essential for legitimate software, these persistence mechanisms are heavily abused by malware including RustBucket (DPRK), Shlayer, and CloudMensis. This detection rule identifies plist file creation in LaunchAgent/LaunchDaemon directories when performed by suspicious processes including scripts executing from temporary directories, unsigned binaries, or scripting interpreters like Python and osascript.

## Attack Chain
An adversary may establish persistence by installing a new launch agent or daemon which executes at login. This involves the creation of a property list file in directories such as /Library/LaunchAgents/ or /Library/LaunchDaemons/ by processes such as scripts executing from temporary directories, unsigned binaries, or scripting interpreters.

## Impact
Successful abuse allows malicious code to achieve persistence, ensuring it executes automatically upon user login or system boot.

## Recommendation
- Examine the file.path to identify the specific plist file created and its location.
- Read the plist contents using plutil or defaults to identify the Program or ProgramArguments configured for execution.
- Analyze the process.executable to understand what created the plist file and assess whether execution from that location is suspicious.
- Check the process.name and process.code_signature fields to determine if the creating process was a scripting interpreter or unsigned binary.
- Locate the binary or script referenced in the plist and calculate its hash for threat intelligence lookups.
- Review the parent process chain to trace back to the initial execution vector.
- Immediately unload the suspicious LaunchAgent or LaunchDaemon using launchctl unload and remove the malicious plist file.
