---
brief_id: brief-2026-11-02-macos-loginhook-persistence
event_id: brief-2026-11-02-macos-loginhook-persistence
revision: 1
activity_at: "2026-11-02T09:08:54Z"
title: macOS Persistence via Login Hook plist Modification
slug: 2026-11-macos-loginhook-persistence
description: Adversaries can achieve persistence on macOS by modifying 'com.apple.loginwindow.plist' to execute malicious scripts or binaries with root privileges via LoginHook or LogoutHook keys.
date: "2026-11-02T09:08:54Z"
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
tags:
  - persistence
  - defense-evasion
  - macos
vendors:
  - Apple
products:
  - macOS
affected_os:
  - macOS
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1037
    technique_name: Boot or Logon Initialization Scripts
    subtechnique_id: T1037.002
    subtechnique_name: Login Hook
    evidence: Adversaries may modify plist files to run a program during system boot or user login for persistence.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1647
    technique_name: Plist File Modification
    evidence: Adversaries can abuse these keys to execute a payload every time a user logs in.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/macos/persistence_loginwindow_plist_modification.toml
  - https://attack.mitre.org/techniques/T1037/002/
rules:
  - title: Detect macOS Persistence via Login Hook
    description: Detects creation or modification of com.apple.loginwindow.plist which may indicate a LoginHook or LogoutHook persistence mechanism.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1037.002
    data_sources:
      - file_event
      - macos
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy file monitoring for com.apple.loginwindow.plist and alert on non-management processes
      owner: Detection Engineering
      due: 48h
      evidence: Source provides specific file name and list of filterable management processes.
  hunt_leads:
    - lead: Identify existing LoginHook or LogoutHook configurations using plutil
      technique_id: T1037.002
      data_needed:
        - Host-level file content inspection
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The source notes hooks are set with defaults write and can be inspected with plutil -p.
  mitigation_plan:
    - priority: immediate
      action: Remove unauthorized LoginHook entries via 'sudo defaults delete com.apple.loginwindow LoginHook'
      owner: SOC
      addresses: T1037.002
      evidence: Source documentation provides the specific remediation command.
---

The `com.apple.loginwindow` preferences domain supports the deprecated `LoginHook` and `LogoutHook` keys, which allow for the execution of arbitrary scripts or binaries with root privileges every time a user logs in or out. Adversaries leverage these keys by writing to the `com.apple.loginwindow.plist` file, typically located in `/var/root/Library/Preferences/`, `/Library/Preferences/`, or `~/Library/Preferences/`. This technique provides a mechanism for automatic execution during system boot or user login.

## Impact

Successful exploitation allows for persistent execution of arbitrary code with root privileges upon every login or logout event on the affected macOS host.

## Recommendation

- Deploy file integrity monitoring to alert on any modification to `com.apple.loginwindow.plist` files across the environment.
- Review all existing `LoginHook` and `LogoutHook` configurations on high-value macOS hosts using `sudo plutil -p /var/root/Library/Preferences/com.apple.loginwindow.plist`.
- Validate modifications against expected configuration management, backup, and system migration activity.
- Remove unauthorized hooks using `sudo defaults delete com.apple.loginwindow LoginHook`.
