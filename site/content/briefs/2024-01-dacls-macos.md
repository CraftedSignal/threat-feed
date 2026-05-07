---
title: Lazarus Group's Dacls RAT Targets macOS
slug: 2024-01-dacls-macos
description: The Lazarus Group is distributing a new variant of the Dacls RAT targeting macOS systems via a trojanized application, installing a hidden executable and attempting persistence.
date: "2024-01-23T17:30:00Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - Lazarus Group
  - HIDDEN COBRA
  - LABYRINTH CHOLLIMA
  - Diamond Sleet
  - Zinc
tags:
  - macos
  - rat
  - lazarus group
vendors:
  - Apple
  - Atlassian
products:
  - TinkaOTP.app
  - Confluence Data Center
affected_os:
  - OS X Yosemite
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1027
    technique_name: Obfuscated Files or Information
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1543
    technique_name: Create or Modify System Process
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1566
    technique_name: Phishing
cves:
  - id: CVE-2019-3396
    cvss: 9.8
    epss: 0.94471
references:
  - https://objective-see.org/blog/blog_0x57.html
iocs:
  - type: hash_sha256
    value: 899e66ede95686a06394f707dd09b7c29af68f95d22136f0a023bfd01390ad53
  - type: hash_sha256
    value: 846d8647d27a0d729df40b13a644f3bffdc95f6d0e600f2195c85628d59f1dc6
ioc_counts:
  hash_sha256: 2
rules:
  - title: Detect Dacls RAT Installation
    description: Detects the installation of the Dacls RAT by monitoring for the copy command used to move the SubMenu.nib file.
    platform: sigma
    severity: high
    tactics:
      - installation
    techniques:
      - T1566.001
    data_sources:
      - process_creation
      - macos
  - title: Detect Dacls RAT Executable
    description: Detects execution of the Dacls RAT executable in the user's Library directory.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - macos
  - title: Detect Dacls RAT Launch Agent Creation Attempt
    description: Detects attempts to create a Launch Agent for persistence, specifically targeting the known Dacls RAT path.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1543.001
    data_sources:
      - file_event
      - macos
rules_count: 3
---

The Lazarus Group, a North Korean APT, is actively distributing a new variant of the Dacls RAT targeting macOS systems. This malware is delivered via a trojanized application named TinkaOTP.app, mimicking previous social engineering tactics employed by the group. Discovered in May 2020, the macOS variant of Dacls RAT shares similarities with its Windows/Linux counterparts, suggesting a cross-platform campaign. Upon execution, the malware installs a hidden executable in the user's Library directory and attempts to establish persistence as a launch agent. The macOS variant exhibits a failed persistence mechanism due to a directory check bug. Researchers speculate potential exploitation of CVE-2019-3396, a Confluence vulnerability, aligning with findings alongside the Windows/Linux version. The Lazarus Group continues to evolve its macOS malware, necessitating proactive detection and response measures.

## Attack Chain

1.  The user downloads and mounts the malicious TinkaOTP.dmg disk image.
2.  The user executes the TinkaOTP.app application.
3.  TinkaOTP.app executes `/bin/cp` to copy `/Volumes/TinkaOTP/TinkaOTP.app/Contents/Resources/Base.lproj/SubMenu.nib` to `~/Library/.mina`.
4.  TinkaOTP.app executes `chmod +x ~/Library/.mina` to set the executable bit on the copied file.
5.  TinkaOTP.app executes the copied file `~/Library/.mina`.
6.  `~/Library/.mina` attempts to create a launch agent file at `/Library/LaunchAgents/com.aex.lop.agent.plist`.
7.  The persistence attempt fails because the `/Library/LaunchAgents` directory does not exist by default.
8.  The RAT establishes command and control with its operators (details not available in source).

## Impact

Successful exploitation leads to the installation of a remote access trojan (RAT) on the victim's macOS system, granting the Lazarus Group unauthorized access. The malware can potentially exfiltrate sensitive data, execute arbitrary commands, and perform other malicious activities. The scope of targeting is currently unknown, but the Lazarus Group has historically targeted financial institutions and cryptocurrency exchanges. The failed persistence mechanism in this variant might limit the long-term impact unless other persistence methods are employed.

## Recommendation

*   Monitor process creations for executions of `/bin/cp` copying files to the user's Library directory, especially with the destination `.mina`, using the "Detect Dacls RAT Installation" Sigma rule.
*   Monitor process creations for executions of the hidden executable `~/Library/.mina` using the "Detect Dacls RAT Executable" Sigma rule.
*   Inspect network connections from non-standard applications to external IPs (requires further analysis to build a rule for this specific threat).
*   Block the identified malicious file hashes (SHA256) from the IOC list at the network and endpoint levels.
*   If running Atlassian Confluence, patch CVE-2019-3396 to prevent potential initial access.
