---
title: PowerShell-Based Keylogging Detection
slug: 2026-09-powershell-keylogging
description: Adversaries utilize PowerShell scripts to interface with user32.dll for monitoring user keystrokes to facilitate credential theft.
date: "2026-09-03T13:40:34Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - credential-access
  - collection
  - powershell
  - windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1056
    technique_name: Input Capture
    evidence: Adversaries may log user keystrokes to intercept credentials as the user types them.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1056.001
    technique_name: Input Capture
    evidence: Adversaries may log user keystrokes to intercept credentials as the user types them.
    confidence_band: high
rules:
  - title: Detect Suspicious PowerShell Keylogging Patterns
    description: Detects the use of Get-Keystrokes or low-level user32.dll API calls via PowerShell for keystroke interception
    platform: sigma
    severity: medium
    tactics:
      - collection
      - credential-access
    techniques:
      - T1056.001
    data_sources:
      - ps_script
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Enable PowerShell Script Block Logging (Event ID 4104) across enterprise.
      owner: IT Operations
      due: 72h
      evidence: Required for visibility into script block content.
  hunt_leads:
    - lead: Search for instances of Get-ProcAddress in Event ID 4104 logs.
      technique_id: T1056.001
      data_needed:
        - ScriptBlockText
      priority: medium
      confidence: high
      disposition: convert_to_detection
      evidence: Source document identifies user32.dll API usage as a primary indicator.
---

Adversaries often use PowerShell to execute memory-resident keylogging scripts as a means of credential harvesting. By leveraging P/Invoke via `Get-ProcAddress` to access low-level Windows APIs such as `GetAsyncKeyState` and `GetForegroundWindow` from `user32.dll`, attackers can capture input from the active window. This technique allows for stealthy keystroke interception without dropping traditional malware binaries to disk, making script block logging essential for visibility. This brief provides detection logic for identifying these specific PowerShell patterns, which are often used in the post-exploitation phase to exfiltrate passwords, PINs, or sensitive session data.

## Impact

Successful deployment of keylogging scripts leads to the unauthorized capture of plaintext credentials, including administrative passwords and multi-factor authentication codes. This compromises the integrity of individual workstations and provides attackers with lateral movement capabilities within the network.

## Recommendation

Detection engineering teams should focus on script visibility and monitoring of suspicious API usage within PowerShell environments.

* Enable PowerShell Script Block Logging (Event ID 4104) across all Windows endpoints to capture the full command execution context.
* Deploy the provided Sigma rule to identify script blocks containing references to `user32.dll` API calls or known keylogging script identifiers.
* Monitor for high-frequency or background PowerShell process activity that does not correlate with known administrative maintenance windows or deployment scripts.
