---
brief_id: brief-2026-11-02-macos-screensaver-persistence
event_id: brief-2026-11-02-macos-screensaver-persistence
revision: 1
activity_at: "2026-11-02T09:09:12Z"
title: 'macOS: Unauthorized screensaver configuration modification'
slug: 2026-11-macos-screensaver-persistence
description: Adversaries can maintain persistence on macOS by modifying screensaver plist files to execute malicious .saver bundles, an activity detectable by monitoring for modifications by untrusted or script-based processes.
date: "2026-11-02T09:09:12Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Rule logic extracted from provided source, requires environment verification.
tags:
  - persistence
  - macos
  - endpoint-detection
vendors:
  - Apple
products:
  - macOS
affected_os:
  - macOS
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1546
    technique_name: Event Triggered Execution
    subtechnique_id: T1546.002
    subtechnique_name: Screensaver
    evidence: An adversary can maintain persistence on a macOS endpoint by creating a malicious screensaver (.saver) file and configuring the screensaver plist file to execute code each time the screensaver is activated.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/macos/persistence_screensaver_plist_file_modification.toml
  - https://posts.specterops.io/saving-your-access-d562bf5bf90b
  - https://github.com/D00MFist/PersistentJXA
rules:
  - title: Detect Unauthorized macOS Screensaver Plist Modification
    description: Detects unauthorized modification of screensaver plist files by untrusted or script-based processes
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1546.002
    data_sources:
      - file_event
      - macos
rules_count: 1
action_plan:
  priority: monitor_or_close
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the screensaver plist modification detection rule
      owner: Detection Engineering
      due: 7d
      evidence: Source provided EQL query logic.
  hunt_leads:
    - lead: Search for unsigned or untrusted processes modifying plist files in Library/Preferences
      technique_id: T1546.002
      data_needed:
        - Process modification events
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Adversaries can drop a malicious .saver bundle and update these plist files.
  mitigation_plan:
    - priority: medium
      action: Enforce code signing for all binaries and scripts managing system settings
      owner: IT Operations
      addresses: T1546.002
      evidence: The rule identifies unauthorized modifications by unsigned or untrusted processes.
  gaps:
    - Telemetry visibility into screensaver module execution.
---

Adversaries can establish persistence on macOS by deploying a malicious screensaver (.saver) bundle and modifying the associated screensaver preference (plist) files. This forces the system to execute the malicious bundle whenever the screensaver activates. Detection focuses on identifying modifications to `com.apple.screensaver.*.plist` files performed by unsigned, untrusted, or common script-based processes.

## Attack Chain

1. Attacker gains initial access to the macOS host.
2. Attacker writes a malicious screensaver (.saver) bundle to a directory such as `~/Library/Screen Savers/`.
3. Attacker uses an untrusted process or script interpreter (e.g., `python`, `osascript`, `perl`) to modify the screensaver preference plist.
4. The system, upon user inactivity or manual activation, triggers the `ScreenSaverEngine`.
5. The screensaver engine loads the malicious .saver bundle.
6. The malicious bundle executes arbitrary code under the context of the active user session.

## Recommendation

- Deploy the provided detection logic to identify unauthorized modifications to screensaver preferences.
- Investigate any process modifying `com.apple.screensaver.*.plist` files that lacks a valid code signature or is a known script interpreter.
- Review the contents of `~/Library/Screen Savers/` and `/Library/Screen Savers/` for unexpected or unsigned .saver bundles.
- Verify that legitimate device management solutions or administrative scripts interacting with plist files are properly signed and identified as authorized.
