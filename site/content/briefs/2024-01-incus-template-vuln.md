---
title: Incus Instance Template Vulnerability CVE-2026-33897
slug: 2024-01-incus-template-vuln
description: A vulnerability in Incus versions prior to 6.23.0 allows for arbitrary read and write access as root on the host server by exploiting a missing chroot isolation in the pongo2 template engine.
date: "2026-03-26T23:16:20Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - incus
  - template-injection
  - privilege-escalation
  - CVE-2026-33897
  - linux
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33897
rules:
  - title: Detect Incus Instance Template Creation
    description: Detects the creation of new Incus instance templates, which could be a precursor to exploiting CVE-2026-33897.
    platform: sigma
    severity: low
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - file_event
      - linux
  - title: Detect Incus Pongo2 Template File Modification
    description: Detects modification of Incus template files containing pongo2 code, potentially indicating exploitation of CVE-2026-33897.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - file_event
      - linux
  - title: Detect Incus Template Execution with File Access Outside Instance
    description: Detects file access attempts outside the expected chroot of an Incus instance during template execution.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - file_event
      - linux
rules_count: 3
---

Incus, a system container and virtual machine manager, is vulnerable to arbitrary read and write access as root due to a flaw in its instance template handling. Prior to version 6.23.0, the application lacks proper chroot isolation when processing pongo2 templates. These templates, intended for file templating within instances during their lifecycle, bypass the expected chroot, granting access to the entire host filesystem with root privileges. This vulnerability, identified as CVE-2026-33897…
