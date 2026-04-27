---
title: MemProcFS Usage for Memory Dump Mounting and Credential Access
slug: 2024-11-memprocfs-memory-dump
description: Adversaries use MemProcFS, a memory forensics tool, to mount memory dumps as virtual file systems and extract sensitive information like credentials from LSASS or registry hives.
date: "2024-11-02T12:00:00Z"
severities:
  - high
tags:
  - credential-access
  - memory-dump
  - memprocfs
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
references:
  - https://github.com/ufrisk/MemProcFS
  - https://0xdf.gitlab.io/2024/10/05/htb-freelancer.html#
  - https://www.huntress.com/blog/curling-for-data-a-dive-into-a-threat-actors-malicious-ttps
rules:
  - title: Detect MemProcFS Execution with Device Parameter
    description: Detects execution of MemProcFS with the '-device' parameter, indicating potential memory dump mounting.
    platform: sigma
    severity: high
    tactics:
      - credential-access
    techniques:
      - T1003
      - T1003.001
      - T1003.002
      - T1003.004
    data_sources:
      - process_creation
      - windows
  - title: Detect MemProcFS Execution from Unusual Location
    description: Detects execution of MemProcFS from non-standard directories, which might indicate suspicious activity.
    platform: sigma
    severity: medium
    tactics:
      - credential-access
    techniques:
      - T1003
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

MemProcFS is a memory forensics tool that allows users to mount physical memory as a virtual file system. While legitimate uses exist for forensic analysis, adversaries are abusing it to gain unauthorized access to sensitive information. Observed tactics involve mounting memory dumps of compromised systems and extracting credentials, LSA secrets, SAM data, and cached domain credentials. This activity is particularly concerning as it allows threat actors to bypass traditional security measures…
