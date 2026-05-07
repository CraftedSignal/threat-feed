---
title: macOS Mojave Beta Webcam and Microphone Access Bypass
slug: 2024-01-macos-mojave-webcam-bypass
description: macOS Mojave beta's new privacy controls can be bypassed by exploiting the entitlements of trusted applications like QuickTime Player via AppleScript to access the webcam and microphone without user consent.
date: "2024-01-09T18:15:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - macos
  - webcam
  - microphone
  - applescript
  - tcc
vendors:
  - Apple
products:
  - macOS Mojave
  - QuickTime Player
  - FaceTime
affected_os:
  - macOS Mojave
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
references:
  - https://objective-see.org/blog/blog_0x2F.html
rules:
  - title: osascript Execution Spawning QuickTime
    description: Detects the execution of osascript potentially running malicious AppleScripts to control QuickTime Player
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1548
    data_sources:
      - process_creation
      - macos
  - title: Suspicious AppleScript Execution via osascript
    description: Detects suspicious AppleScript execution via osascript, which could indicate malicious activity.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1548
    data_sources:
      - process_creation
      - macos
rules_count: 2
---

In June 2018, a bypass was discovered in the macOS Mojave (10.14) beta (18A293u) that allowed unauthorized access to the microphone and webcam, despite Apple's claims of new data protections requiring user permission. The bypass leverages applications with existing entitlements to access the microphone and camera, such as QuickTime Player and FaceTime. By utilizing AppleScript to control these applications, malicious actors can record audio and video without triggering the expected permission prompts. This circumvents the intended security enhancements designed to prevent surreptitious access to sensitive user devices. While Apple stated that the final version of macOS Mojave would mitigate this attack, the initial beta release was vulnerable.

## Attack Chain

1. An attacker crafts an AppleScript designed to interact with QuickTime Player.
2. The AppleScript uses QuickTime Player's built-in recording capabilities.
3. The AppleScript initiates a new movie recording via QuickTime Player.
4. The AppleScript sets a delay to record audio and video for a specified duration.
5. The AppleScript pauses and saves the movie recording to a file.
6. The attacker executes the AppleScript using `osascript`.
7. QuickTime Player, due to its existing entitlements, accesses the webcam and microphone without prompting the user for permission.
8. The attacker retrieves the saved recording containing audio and video captured without user consent, potentially exfiltrating this data.

## Impact

The vulnerability in macOS Mojave beta allowed unauthorized access to a user's webcam and microphone, potentially enabling surveillance without their knowledge or consent. While the number of affected users during the beta phase is unknown, the potential for privacy violations was significant. Successful exploitation could result in the compromise of sensitive information, including personal conversations and visual data. This can lead to reputational damage, blackmail, or other malicious activities targeting the victim.

## Recommendation

*   Deploy the "osascript Execution Spawning QuickTime" Sigma rule to detect the execution of osascript to run AppleScripts that control QuickTime Player.
*   Monitor process execution for `osascript` with arguments that point to suspicious `.scpt` files using the "Suspicious AppleScript Execution via osascript" Sigma rule.
*   Enable process creation logging and file creation events to facilitate the detection of malicious AppleScripts and their execution.
