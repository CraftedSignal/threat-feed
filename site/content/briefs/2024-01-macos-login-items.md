---
title: Detecting Persistence via Parsing macOS Login Item Files
slug: 2024-01-macos-login-items
description: This brief details a method for parsing macOS login item files to detect persistence mechanisms employed by malware or threat actors.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - macos
vendors:
  - Apple
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
references:
  - https://objective-see.org/blog/blog_0x31.html
rules:
  - title: Detect Login Items Launching from Suspicious Locations
    description: Detects processes launched from standard login item locations that are not signed by Apple or a known developer.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - process_creation
      - macos
  - title: Detect Modification of Login Items via Defaults Command
    description: Detects the use of the 'defaults' command to modify login items, which can be indicative of malicious persistence activity.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - process_creation
      - macos
rules_count: 2
---

Apple has updated the way login items are stored in macOS, impacting how persistence mechanisms are implemented and detected. This brief outlines a method, described by Objective-See, for parsing these login item files to identify malicious persistence techniques. This method is essential for defenders as attackers frequently abuse login items to automatically execute malicious code upon user login, ensuring continued access to compromised systems. This technique is relevant to all recent versions of macOS.

## Attack Chain

1.  The attacker gains initial access to the macOS system, potentially through social engineering or exploiting a software vulnerability.
2.  The attacker drops a malicious executable or script onto the filesystem (e.g., `/tmp/evil.sh`).
3.  The attacker modifies or creates a new login item file to point to the malicious executable or script. These files are typically located in `~/Library/LaunchAgents` or `/Library/LaunchDaemons`.
4.  The attacker leverages the `defaults` command or directly modifies the plist file associated with the login item to configure it to execute the malicious payload.
5.  The system automatically executes the malicious script or binary specified in the login item file when the user logs in.
6.  The executed payload performs malicious activities, such as establishing a reverse shell, exfiltrating data, or installing further malware components.
7.  The attacker maintains persistence across system reboots or user logouts/logins.

## Impact

Successful exploitation allows attackers to establish persistence on macOS systems, enabling them to maintain long-term access and control. This can lead to data theft, system compromise, and further propagation of malware within the network. The impact is significant as it ensures the attacker's code executes automatically, bypassing standard security measures.

## Recommendation

*   Enable process creation logging on macOS to detect malicious processes launched via login items.
*   Implement the Sigma rule provided below to detect suspicious processes launching from standard login item locations.
*   Regularly audit login items on macOS systems to identify and remove unauthorized entries.
*   Monitor file creation and modification events within the `~/Library/LaunchAgents` and `/Library/LaunchDaemons` directories for suspicious activity.
