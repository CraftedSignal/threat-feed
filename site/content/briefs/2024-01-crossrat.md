---
title: CrossRAT Multi-Platform Surveillanceware Analysis
slug: 2024-01-crossrat
description: CrossRAT is a Java-based, multi-platform surveillance tool targeting Windows, macOS, and Linux systems, capable of file system manipulation, screenshot capture, and persistence.
date: "2024-01-03T17:31:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - crossrat
  - rat
  - persistence
  - surveillanceware
vendors:
  - Apple
products:
  - Mac OS X
affected_os:
  - MacOS
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1543
    technique_name: Create or Modify System Process
references:
  - https://objective-see.org/blog/blog_0x28.html
rules:
  - title: Detect CrossRAT Execution via Java
    description: Detects the execution of CrossRAT via the java -jar command
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1204.002
    data_sources:
      - process_creation
      - windows
  - title: Detect CrossRAT macOS Persistence
    description: Detects the creation of a Launch Agent plist file used by CrossRAT for persistence on macOS
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1543.001
    data_sources:
      - file_event
      - macos
rules_count: 2
---

CrossRAT is a cross-platform implant discovered by the EFF/Lookout and analyzed by Objective-See. Written in Java, this malware targets Windows, macOS, and Linux systems. The malware sample analyzed was named 'hmar6.jar'. CrossRAT possesses capabilities such as manipulating the file system, capturing screenshots, and running arbitrary DLLs on Windows systems for secondary infection. It focuses on establishing persistence on infected systems to ensure continued access. The malware gathers OS-specific information to tailor its actions on the compromised host and communicate effectively with its command and control server.

## Attack Chain

1.  The malware, typically a JAR file (e.g., hmar6.jar), is executed on the target system, requiring Java Runtime Environment.
2.  CrossRAT identifies the operating system (Windows, macOS, or Linux) using `System.getProperty("os.name")` and OS-specific commands like `/usr/bin/sw_vers` on macOS or examining `/etc/os-release` on Linux.
3.  The malware establishes persistence. On macOS, it creates a Launch Agent in `/Library/LaunchAgents/` or `/Users/<user>/Library/LaunchAgents/`, writing a plist file.
4.  The Launch Agent plist configures the system to execute the malware (java -jar <malware.jar>) upon system startup via the "RunAtLoad" key.
5.  The malware gathers system information, including OS version, kernel build, and architecture, by executing commands such as `uname -a`.
6.  CrossRAT establishes communication with its command and control (C2) server to receive further instructions.
7.  Based on the instructions from the C2, CrossRAT manipulates the file system, takes screenshots, or executes arbitrary DLLs (on Windows).

## Impact

CrossRAT allows attackers to perform surveillance activities on infected systems. Successful infection enables exfiltration of sensitive data, manipulation of files, and persistent access to the compromised system. The cross-platform nature of CrossRAT enables attackers to target a wide range of victims regardless of their operating system.

## Recommendation

*   Monitor process creation events for the execution of `java -jar` from unusual locations, as this is a common method for launching CrossRAT (see rule: "Detect CrossRAT Execution via Java").
*   Monitor the creation of new Launch Agents in `/Library/LaunchAgents/` or `/Users/<user>/Library/LaunchAgents/` directories on macOS, specifically those executing JAR files (see rule: "Detect CrossRAT macOS Persistence").
*   Inspect network connections originating from Java processes for suspicious command and control traffic.
