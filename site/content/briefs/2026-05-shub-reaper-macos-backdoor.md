---
title: SHub Reaper Stealer Backdoors macOS with Multi-Brand Spoofing
slug: 2026-05-shub-reaper-macos-backdoor
description: The SHub Reaper stealer combines credential theft, wallet hijacking, and document exfiltration with persistent backdoor access on macOS, distributed through fake WeChat and Miro installers while spoofing Apple, Google, and Microsoft to evade detection.
date: "2026-05-19T19:53:19Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - macos
  - infostealer
  - backdoor
  - social-engineering
  - applescript
vendors:
  - Apple
  - Google
  - Microsoft
products:
  - WeChat
  - Miro
  - macOS Script Editor
  - Google Software Update
affected_os:
  - macos
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1204
    technique_name: User Execution
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1543
    technique_name: Create or Modify System Process
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://www.darkreading.com/threat-intelligence/stealer-spoofs-google-microsoft-apple-backdoors-macos
rules:
  - title: Detect osascript Spawning Curl or Shell Interpreters
    description: Detects osascript (AppleScript interpreter) spawning curl or shell interpreters, indicative of malicious AppleScript execution.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - macos
  - title: Detect Browser to AppleScript Execution Chain
    description: Detects browser processes initiating AppleScript execution via the applescript:// URL scheme, potentially indicating malicious activity.
    platform: sigma
    severity: medium
    tactics:
      - execution
      - initial_access
    techniques:
      - T1218
    data_sources:
      - process_creation
      - macos
  - title: Detect Suspicious Script Editor Usage
    description: Detects unexpected use of Script Editor.app which may indicate malicious applescript execution.
    platform: sigma
    severity: low
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - macos
rules_count: 3
---

The SHub Reaper stealer is a macOS infostealer that blends traditional stealer functionality with persistent backdoor capabilities. It is distributed through social engineering lures such as fake WeChat and Miro installers. This malware demonstrates a shift in macOS malware behavior, moving away from ClickFix social engineering to Apple script-based execution to evade detection. SHub Reaper leverages a unique multi-brand spoofing technique, impersonating Apple, Google, and Microsoft across the infection chain. The malware installs a fake Google Update framework to maintain persistence and establishes a backdoor, allowing for arbitrary command execution and continuous compromise of the infected system. This represents an evolution in macOS infostealers, combining "smash-and-grab" data theft with long-term access and control.

## Attack Chain

1.  The attack starts with malicious web pages offering fake Miro and WeChat installers.
2.  Victims download and execute the fake installers, initiating the infection chain.
3.  The malware may be hosted on a typosquatted Microsoft domain.
4.  The installer executes under the guise of a fake Apple security update.
5.  SHub Reaper installs a fake Google Update framework under the user Library paths for persistence.
6.  A LaunchAgent is registered using Google Keystone-style naming conventions to ensure the malware runs regularly.
7.  The malware beacons to a command and control server every 60 seconds, supporting arbitrary command execution.
8.  The malware steals credentials, hijacks crypto wallets, and exfiltrates documents while maintaining persistent backdoor access.

## Impact

Successful SHub Reaper infections can lead to significant data loss, including sensitive credentials, cryptocurrency assets, and confidential documents. The persistent backdoor allows attackers to maintain long-term access to compromised systems, enabling further data theft, command execution, and potential lateral movement within the network. The shift from ClickFix tactics to AppleScript execution renders traditional terminal-centric detections ineffective, increasing the risk of successful compromise. This combination of stealer and backdoor capabilities makes SHub Reaper a particularly dangerous threat to macOS users.

## Recommendation

*   Monitor for unexpected invocations of Script Editor (`Script Editor.app`) to detect potential AppleScript-based execution, as outlined by SentinelOne's report.
*   Deploy the Sigma rule detecting `osascript` spawning `curl` or shell interpreters to identify malicious AppleScript activity.
*   Implement the Sigma rule for detecting browser-to-AppleScript execution chains to identify potential initial access vectors.
*   Educate macOS users to be wary of software installers from untrusted sources and to verify the authenticity of software updates, as this is the primary infection vector.
*   Monitor user Library paths for the installation of unexpected Google Update frameworks and LaunchAgents with Google Keystone-style naming conventions, as these are indicators of persistence.
