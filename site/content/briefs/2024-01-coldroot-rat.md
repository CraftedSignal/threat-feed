---
title: Coldroot RAT Targeting macOS
slug: 2024-01-coldroot-rat
description: The Coldroot RAT is a cross-platform backdoor targeting macOS systems, providing remote attackers persistent access through a launch daemon, masquerading as an Apple audio driver, and beaconing to a command and control server.
date: "2024-01-03T18:10:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - rat
  - macos
  - persistence
  - coldroot
vendors:
  - Apple
products:
  - macOS
affected_os:
  - macOS
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1543
    technique_name: Create or Modify System Process
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1027
    technique_name: Obfuscated Files or Information
references:
  - https://objective-see.org/blog/blog_0x2A.html
iocs:
  - type: hash_sha256
    value: c20980d3971923a0795662420063528a43dd533d07565eb4639ee8c0ccb77fdf
  - type: filename
    value: conx.wol
ioc_counts:
  filename: 1
  hash_sha256: 1
rules:
  - title: Detect Coldroot Launch Daemon Installation
    description: Detects the installation of a launch daemon by Coldroot RAT via cp and launchctl.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1543.001
    data_sources:
      - process_creation
      - macos
  - title: Detect Coldroot Launch Daemon File Creation
    description: Detects the creation of Coldroot's launch daemon file.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1543.001
    data_sources:
      - file_event
      - macos
rules_count: 2
---

The Coldroot RAT is a cross-platform backdoor that targets macOS systems. This RAT masquerades as a legitimate Apple audio driver to avoid detection. Discovered in early January 2018, the malware persists on infected systems by installing a launch daemon, ensuring it is automatically restarted after each reboot. The malware beacons out to a command and control (C2) server for tasking, and also functions as a keylogger. It attempts to modify the TCC.db database, but this functionality is thwarted by System Integrity Protection (SIP). This RAT poses a significant threat to macOS users as it can provide unauthorized access to sensitive data and allow attackers to maintain persistent control over compromised systems.

## Attack Chain

1.  The user downloads a DMG file containing the malicious application bundle, `com.apple.audio.driver.app`.
2.  The user executes the application, which prompts for user credentials via a standard authentication prompt.
3.  The malware loads its settings from `com.apple.audio.driver.app/Contents/MacOS/conx.wol`, which contains C2 information and other configuration.
4.  The malware copies itself to `/private/var/tmp/com.apple.audio.driver.app/Contents/MacOS/com.apple.audio.driver`.
5.  The malware creates a launch daemon plist file at `/Library/LaunchDaemons/com.apple.audio.driver.plist`.
6.  The malware uses `/bin/cp` to install the launch daemon plist.
7.  The malware uses `/bin/launchctl` to launch the newly installed launch daemon.
8.  The malware beacons to the C2 server specified in the `conx.wol` file, awaiting further commands, and logs keystrokes to `adobe_logs.log`.

## Impact

Successful infection by the Coldroot RAT allows attackers to maintain persistent access to macOS systems. The malware's keylogging capabilities enable attackers to steal credentials and sensitive information. While the malware attempts to modify the TCC.db database, SIP prevents this action. However, the persistent access and data theft capabilities still pose a significant risk. The number of victims and specific sectors targeted are currently unknown.

## Recommendation

*   Monitor process executions for the use of `/bin/cp` and `/bin/launchctl` to install launch daemons, as highlighted in the attack chain. Deploy the `Detect Coldroot Launch Daemon Installation` Sigma rule to detect this behavior.
*   Monitor network connections to the C2 server IP address `45.77.49.118` listed in the IOC table and block the domain at the firewall.
*   Implement file integrity monitoring for `/Library/LaunchDaemons/com.apple.audio.driver.plist` to detect unauthorized modifications of launch daemons. Deploy the `Detect Coldroot Launch Daemon File Creation` Sigma rule to detect the creation of this launch daemon.
*   Scan systems for files matching the SHA256 hash `c20980d3971923a0795662420063528a43dd533d07565eb4639ee8c0ccb77fdf` to identify potentially infected machines.
