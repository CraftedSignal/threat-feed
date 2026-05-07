---
title: OSX.NetWire.A Backdoor Dropped via Firefox 0-day
slug: 2024-01-osx-netwire
description: A Firefox zero-day exploit was used to target Mac users, resulting in the installation of the OSX.NetWire.A malware, which establishes persistence and communicates with a command and control server.
date: "2024-01-03T14:30:00Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
tags:
  - osx
  - malware
  - backdoor
vendors:
  - Mozilla
  - Apple
products:
  - Firefox
  - macOS
affected_os:
  - macOS
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1543
    technique_name: Create or Modify System Process
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
references:
  - https://objective-see.org/blog/blog_0x44.html
iocs:
  - type: ip
    value: 89.34.111.113
  - type: hash_md5
    value: DE3A8B1E149312DAC5B8584A33C3F3C6
  - type: hash_sha1
    value: 23017A55B3D25A2597B7148214FD8FB2372591A5
  - type: hash_sha256
    value: 07A4E04EE8B4C8DC0F7507F56DC24DB00537D4637AFEE43DBB9357D4D54F6FF4
ioc_counts:
  hash_md5: 1
  hash_sha1: 1
  hash_sha256: 1
  ip: 1
rules:
  - title: Detect OSX.NetWire.A Launch Agent Persistence
    description: Detects the creation of a malicious launch agent file associated with OSX.NetWire.A persistence.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1543.001
    data_sources:
      - file_event
      - macos
  - title: Detect OSX.NetWire.A File Creation
    description: Detects the creation of files in the ~/.defaults/Finder.app directory, where OSX.NetWire.A copies itself.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    data_sources:
      - file_event
      - macos
  - title: Detect OSX.NetWire.A Finder.app execution
    description: Detects execution of the OSX.NetWire.A sample from non-standard location
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1569.002
    data_sources:
      - process_creation
      - macos
rules_count: 3
---

In June 2019, a Firefox zero-day exploit was leveraged to target employees at cryptocurrency exchanges, leading to the deployment of the OSX.NetWire.A malware on macOS systems. The malware, identified as Finder.app (SHA256: 07A4E04EE8B4C8DC0F7507F56DC24DB00537D4637AFEE43DBB9357D4D54F6FF4), employs techniques to ensure persistent execution, including the use of launch agents and login items. The malware decrypts configuration data to reveal its command and control (C2) server address and is capable of remote tasking, indicating potential for data exfiltration or further malicious activities. Its capabilities include taking screenshots and simulating synthetic events, providing the attacker with extensive control over the compromised system.

## Attack Chain

1.  A user visits a malicious website hosting a Firefox zero-day exploit.
2.  The exploit successfully executes, bypassing security measures in Firefox.
3.  The exploit downloads and executes the initial stage of OSX.NetWire.A, disguised as Finder.app.
4.  The malware copies itself to ~/.defaults/Finder.app to establish a persistent presence.
5.  The malware creates a launch agent (~/Library/LaunchAgents/com.mac.host.plist) to ensure execution upon user login.
6.  OSX.NetWire.A decrypts its embedded configuration data, including the C2 server address (89.34.111.113:443).
7.  The malware communicates with the C2 server to receive commands.
8.  Based on the commands received, the malware performs actions such as taking screenshots or simulating user events.

## Impact

The OSX.NetWire.A malware poses a significant threat to macOS users, particularly those in the cryptocurrency sector. A successful compromise can lead to unauthorized access to sensitive information, financial loss, and reputational damage. The malware's remote tasking capabilities allow attackers to perform a wide range of malicious activities, including data exfiltration, surveillance, and potentially lateral movement within the compromised network. The number of victims is unknown, but the targeting of cryptocurrency exchanges suggests a high-value objective.

## Recommendation

*   Deploy the "Detect OSX.NetWire.A Launch Agent Persistence" Sigma rule to identify malicious launch agents created by the malware to ensure persistence on compromised systems.
*   Block the C2 IP address (89.34.111.113) identified in the malware's decrypted configuration data at the firewall to prevent communication and further compromise.
*   Monitor file creation events for the creation of files in the `~/.defaults/Finder.app` directory using the "Detect OSX.NetWire.A File Creation" Sigma rule, as this is the location where the malware copies itself.
