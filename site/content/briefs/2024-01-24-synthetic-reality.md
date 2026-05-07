---
title: macOS Synthetic Mouse Event Vulnerabilities
slug: 2024-01-24-synthetic-reality
description: macOS is vulnerable to synthetic mouse event attacks, allowing threat actors to bypass security mechanisms and interact with protected UI components to perform unauthorized actions like dumping keychains and loading kernel extensions.
date: "2024-01-24T12:00:00Z"
type: threat
types:
  - threat
severities:
  - critical
exploited: true
tags:
  - macos
  - synthetic events
  - privilege escalation
  - defense evasion
vendors:
  - Apple
products:
  - macOS
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070.001
    technique_name: 'Indicator Removal on Host: Clear Windows Event Logs'
cves:
  - id: CVE-2017-7150
    cvss: 5.5
    epss: 0.00069
references:
  - https://objective-see.org/blog/blog_0x36.html
rules:
  - title: Detect Programmatic Mouse Keys Activation via AppleScript
    description: Detects the use of AppleScript to programmatically enable Mouse Keys, a technique used to bypass macOS security prompts.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1059.003
    data_sources:
      - process_creation
      - macos
  - title: Detect Synthetic Mouse Event Generation via CoreGraphics
    description: Detects processes using CoreGraphics APIs to generate synthetic mouse events, potentially bypassing user interaction requirements.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - privilege_escalation
    data_sources:
      - process_creation
      - macos
  - title: Detect AppleScript Keycode Injection for Mouse Clicks
    description: Detects the use of AppleScript to inject specific keycodes (e.g., 87 for numpad 5) which, when Mouse Keys are enabled, simulate mouse clicks.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - privilege_escalation
    data_sources:
      - process_creation
      - macos
rules_count: 3
---

This brief discusses a class of vulnerabilities on macOS that can be exploited through the programmatic generation of synthetic mouse events. These vulnerabilities allow attackers to bypass security mechanisms designed to protect user privacy and system integrity. The report references historic malware examples abusing synthetic events like OSX.FruitFly and OSX.DevilRobber, discusses CVE-2017-7150, and highlights unpatched 0-day vulnerabilities as of 2018. Attackers can manipulate UI prompts, including security alerts, privacy requests, and the "User Assisted Kernel Loading" interface, enabling malicious activities such as keychain theft, geolocation tracking, and unauthorized kernel extension loading. The core issue lies in the OS trusting synthetic events originating from internal processes or specific input methods like "Mouse Keys". This creates a significant attack surface, particularly on older macOS versions, where protections against synthetic events are incomplete.

## Attack Chain

1.  Gain initial access to the macOS system through an unspecified method (e.g., exploiting a separate vulnerability, social engineering).
2.  The attacker programmatically enables "Mouse Keys" via AppleScript, using `System Preferences` to reveal the `com.apple.preference.universalaccess` pane and then sending synthetic mouse clicks to enable the feature.
3.  The attacker moves the mouse cursor to a target UI element (e.g., an "Allow" button on a security prompt) using `CGEventCreateMouseEvent` to create a mouse move event.
4.  The attacker sends a "synthetic" keyboard event with keycode 87 (numberpad 5) via AppleScript, triggering a mouse click due to "Mouse Keys" being enabled.
5.  The OS converts the keyboard event into a trusted mouse click, bypassing protections on the target UI component.
6.  The attacker leverages the bypassed UI prompt to perform unauthorized actions, such as dismissing privacy alerts related to geolocation access.
7.  The attacker programmatically accesses sensitive data (e.g., geolocation information) that would normally require user consent.
8.  The attacker exfiltrates the stolen data or uses the elevated privileges to further compromise the system.

## Impact

Successful exploitation allows attackers to bypass macOS security mechanisms, potentially impacting a large number of users. Attackers can steal sensitive information like keychain data, access private user data (geolocation, contacts, calendar), and load malicious kernel extensions without user consent. This can lead to complete system compromise, data theft, and persistent malware infections. The report highlights that privacy-related alerts can be trivially bypassed, raising serious concerns about user data protection. The ease of exploitation, especially with "Mouse Keys," makes this a critical vulnerability.

## Recommendation

*   Monitor for processes enabling "Mouse Keys" via AppleScript or command-line tools; create a Sigma rule based on `process_creation` events targeting `osascript` executing commands related to `com.apple.preference.universalaccess`.
*   Detect the use of `CGPostMouseEvent` or `CGEventCreateMouseEvent` API calls, especially when combined with AppleScript execution, to identify potential synthetic event generation.
*   Audit and monitor processes accessing sensitive user data (geolocation, contacts, calendar) after the execution of AppleScript or CoreGraphics functions, to identify potential exploitation of synthetic event vulnerabilities.
*   Monitor for the execution of AppleScript commands that simulate key presses (e.g., `key code 87`) especially following mouse movement events, as this may indicate abuse of the Mouse Keys feature.
