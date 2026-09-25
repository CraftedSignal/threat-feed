---
title: PamStealer macOS Malware Updates with Server-Side Decryption and Multi-Layer Persistence
slug: 2026-09-pamstealer
description: The updated PamStealer macOS malware employs a server-side decryption mechanism and advanced multi-layer persistence, including Git hooks and LaunchAgents, to steal credentials and system data.
date: "2026-09-25T16:26:33Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - macos
  - malware
  - stealer
  - credential-theft
affected_os:
  - macOS
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.002
    technique_name: JavaScript
    evidence: The latest artifacts, per Jamf Threat Labs, continue to rely on the same JavaScript for Automation (JXA) dropper mechanism
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547.001
    technique_name: Launch Agent
    evidence: Installing four redundant persistence methods via LaunchAgent
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548.002
    technique_name: Bypass User Account Control
    evidence: Suppressing macOS notifications that alert users when a new background login item is added
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555.003
    technique_name: Credentials from Web Browsers
    evidence: Steal credentials from Chromium- and Firefox-based browsers
    confidence_band: high
references:
  - https://thehackernews.com/2026/09/pamstealer-macos-malware-adds-live-c2.html
iocs:
  - type: domain
    value: wavel.app
  - type: domain
    value: wavel.apple03cloudstore.com
ioc_counts:
  domain: 2
rules:
  - title: Detect Suspicious Global Git Hook Path Configuration
    description: Detects attempts to set a global Git core.hooksPath, which can be used for malware persistence via Git hooks.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - process_creation
      - macos
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Block domain wavel.app and wavel.apple03cloudstore.com at the DNS level
      owner: SOC
      due: 24h
      evidence: IOC list extracted from source
  hunt_leads:
    - lead: Search for instances of 'git config --global core.hooksPath' in historical process logs
      technique_id: T1547.001
      data_needed:
        - Process creation events
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Attacker uses git hooks for persistence
  mitigation_plan:
    - priority: immediate
      action: Remove unauthorized Git hooks from ~/Library/Application Support/System/.githooks/
      owner: IT Operations
      addresses: Persistence mechanism
      evidence: Repair script location identified in source
---

PamStealer, a macOS-targeting stealer, has evolved to incorporate a server-side decryption chain, significantly hindering static analysis. The malware is distributed via a fake cryptocurrency wallet website ("wavel.app"), replacing previous lures related to tools like Maccy and Scoppr. Upon execution, the malware performs an X25519 key exchange with a C2 server ("wavel.apple03cloudstore.com") to recover its primary Swift-based payload. This design ensures that the payload cannot be decrypted without active C2 cooperation, preventing researchers from statically analyzing the stealer component. The malware implements aggressive multi-layer persistence using LaunchAgents, a repair script, and malicious Git hooks that trigger execution upon every repository checkout or commit. Once installed, the Swift-based stealer harvests passwords, browser credentials from a wide array of Chromium and Firefox-based browsers, and user-centric files like .zsh_history. This variant demonstrates increased investment in delivery infrastructure and evasion techniques.

## Attack Chain

1. A victim visits the fraudulent website "wavel[.]app" and downloads a disk image ("Wavel.dmg") masquerading as a cryptocurrency wallet installer.
2. The user opens a compiled AppleScript within the DMG, which triggers the macOS Script Editor to execute a malicious JXA (JavaScript for Automation) dropper.
3. The JXA dropper base64-decodes a payload and pipes it into "/bin/zsh -s", executing a background shell script.
4. The zsh dropper fetches a decryption utility ("pkgunpack") from "wavel.apple03cloudstore[.]com" and completes an X25519 key exchange with the C2 server to receive the Data Encryption Key (DEK).
5. The decrypted Swift-based stealer payload is staged on the system.
6. The malware establishes persistence by creating a LaunchAgent and injecting a repair script into "~/Library/Application Support/System/.githooks/" which is activated by global Git configuration ("git config --global core.hooksPath").
7. The stealer component enumerates keychain items, browser credentials, and local system metadata before exfiltrating the data to the C2 server.

## Impact

Successful compromise results in the theft of browser-stored credentials, keychain items, and sensitive user files. The malware targets a broad range of Chromium- and Firefox-based browsers (including Arc, Zen, and Brave), increasing the scope of credential exfiltration. The use of ephemeral key exchange prevents static detection of the stealer, enabling long-term persistence via Git hooks and LaunchAgents.

## Recommendation

* Deploy detection rules targeting the execution of JXA scripts from untrusted Disk Images.
* Monitor for unauthorized changes to the global Git configuration, specifically the `core.hooksPath` setting, using file integrity monitoring or audit logs.
* Block communication with the identified C2 infrastructure at the network perimeter.
* Implement endpoint policies to restrict the execution of scripts in `~/Library/Application Support/` and other non-standard execution paths.
* Enable Sysmon for macOS or similar telemetry to track process lineage and shell executions originating from Script Editor.
