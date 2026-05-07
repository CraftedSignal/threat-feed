---
title: Firefox 0-day Drops OSX.Mokes.B Backdoor on macOS
slug: 2024-01-29-firefox-0day-mokes
description: A Firefox 0-day exploit was used to target Mac users, dropping a second backdoor identified as a new variant of the cross-platform Mokes malware (OSX.Mokes.B) with screen capture, audio capture, and document exfiltration capabilities.
date: "2024-01-29T12:00:00Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
tags:
  - malware
  - backdoor
  - osx.mokes
  - macos
  - firefox
vendors:
  - Mozilla
  - Apple
  - Kaspersky
products:
  - Firefox
  - macOS
  - OSX.Mokes
affected_os:
  - macOS
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1543
    technique_name: Create or Modify System Process
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1113
    technique_name: Screen Capture
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1053
    technique_name: Scheduled Task/Job
references:
  - https://objective-see.org/blog/blog_0x45.html
iocs:
  - type: ip
    value: 185.49.69.210
ioc_counts:
  ip: 1
rules:
  - title: Process Created from User Library Directory
    description: Detects processes executing from user library directories, often used by malware for installation and persistence.
    platform: sigma
    severity: high
    tactics:
      - execution
      - persistence
    techniques:
      - T1053.005
    data_sources:
      - process_creation
      - macos
  - title: OSX.Mokes C2 Communication
    description: Detects network connections to known OSX.Mokes command and control servers.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - macos
rules_count: 2
---

In June 2019, a Firefox 0-day exploit was leveraged to target employees at various cryptocurrency exchanges, deploying a previously unknown variant of the OSX.Mokes backdoor. This new variant, dubbed OSX.Mokes.B, shares significant code overlap and capabilities with the original OSX.Mokes discovered by Kaspersky in 2016. The malware, a 13MB 64-bit Mach-O binary, was initially undetected by VirusTotal engines. It installs itself under various names (quicklookd, storeaccountd), persists via launch agents, and communicates with a command and control server. The malware possesses capabilities including screen capture, audio recording, and the ability to discover and exfiltrate documents. The binaries are often very large due to statically linked libraries like OpenSSL. This campaign highlights the continued relevance of older malware families adapted for modern exploits and the importance of behavior-based detection to supplement signature-based AV.

## Attack Chain

1.  Initial Access: A Firefox 0-day exploit is used to compromise a macOS system.
2.  Malware Dropper: The exploit drops a Mach-O executable (mac) to the /Users/<user>/Desktop/ directory.
3.  Installation: The malware copies itself to a location in the user's Library directory, such as ~/Library/Dropbox/quicklookd or ~/Library/App Store/storeaccountd.
4.  Persistence: A launch agent plist file (e.g., quicklookd.plist or storeaccountd.plist) is created in ~/Library/LaunchAgents/ to ensure persistence across reboots. The plist file sets the "RunAtLoad" key to 1.
5.  Execution: The malware executes the copied binary from its new location using execve.
6.  Command and Control: The malware initiates an outbound TCP connection to the C2 server at 185.49.69.210 over HTTP.
7.  Data Collection: The malware leverages AVFoundation frameworks to capture screen and audio recordings.
8.  Data Exfiltration: The malware searches for and exfiltrates documents with extensions like *.doc, *.docx, *.xls, and *.xlsx.

## Impact

Successful infection leads to persistent remote access, allowing the attacker to capture sensitive information, including screen recordings, audio, and documents. This can result in financial loss, intellectual property theft, and reputational damage. While the specific number of victims is unknown, the targeting of cryptocurrency exchanges suggests a focus on high-value targets. The malware's capabilities align with those of a fully-featured backdoor, providing extensive control over compromised systems.

## Recommendation

*   Monitor process creations for executables running from non-standard directories like ~/Library/Dropbox/ or ~/Library/App Store/ using the "Process Created from User Library Directory" Sigma rule.
*   Deploy the "OSX.Mokes C2 Communication" Sigma rule to detect network connections to the identified C2 server IP address (185.49.69.210).
*   Monitor for the creation of LaunchAgent plists that execute binaries from atypical installation paths, especially those masquerading as common system processes or applications based on the persistence steps described above.
*   Inspect network traffic for connections to 185.49.69.210 on port 80, and analyze the HTTP traffic for command and control patterns.
