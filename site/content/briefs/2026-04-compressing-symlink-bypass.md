---
title: compressing npm Package Symlink Bypass Vulnerability
slug: 2026-04-compressing-symlink-bypass
description: A vulnerability in the `compressing` npm package (<=v2.1.0) allows for arbitrary file overwrite via symlink path traversal, bypassing a previous patch for CVE-2026-24884.
date: "2026-04-18T12:00:00Z"
severities:
  - critical
tags:
  - npm
  - supply-chain
  - symlink
  - directory-traversal
  - privilege-escalation
  - arbitrary-file-overwrite
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1564
    technique_name: Hide Artifacts
  - tactic_id: TA0006
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-24884
    cvss: 8.4
    epss: 8e-05
references:
  - https://github.com/advisories/GHSA-4c3q-x735-j3r5
ioc_counts:
  url: 1
rules:
  - title: Detect File Writes Following Symlinks
    description: Detects file writes to unexpected locations that are targeted via symlinks.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1548.001
    data_sources:
      - file_event
      - linux
  - title: Detect Node.js Processes Loading Compressing Module with Network Connections
    description: Detects network connections initiated by Node.js processes that have loaded the `compressing` module, potentially indicating post-exploitation activity.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - linux
  - title: Detect suspicious symlink creation
    description: Detects the creation of suspicious symlinks, which are often used in path traversal attacks.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1564.001
    data_sources:
      - file_event
      - linux
rules_count: 3
---

The `compressing` npm package (v2.1.0 and earlier) contains a critical vulnerability that permits arbitrary file overwrites due to a symlink path traversal bypass. This bypass affects the patch for CVE-2026-24884. The vulnerability arises from an incomplete validation in the `isPathWithinParent` utility, where path string checks are performed without verifying the filesystem state, specifically symbolic links. By cloning a malicious repository containing a pre-existing symbolic link, a victim…
