---
title: libssh Insecure Configuration Allows Local MITM Attacks (CVE-2025-14821)
slug: 2026-04-libssh-mitm
description: CVE-2025-14821 in libssh allows local man-in-the-middle attacks, SSH downgrade attacks, and trusted host manipulation due to insecure default configuration loading from a world-writable directory on Windows.
date: "2026-04-07T17:16:25Z"
severities:
  - high
tags:
  - libssh
  - mitm
  - windows
  - cve-2025-14821
  - insecure-configuration
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
cves:
  - id: CVE-2025-14821
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2025-14821
rules:
  - title: Detect Creation of C:\etc Directory by Non-System Processes
    description: Detects the creation of the C:\etc directory, which could be an indicator of CVE-2025-14821 exploitation.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    data_sources:
      - file_event
      - windows
  - title: Detect Modification of SSH Config in C:\etc
    description: Detects modification of ssh_config file in the C:\etc directory.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    data_sources:
      - file_event
      - windows
rules_count: 2
---

A critical vulnerability, CVE-2025-14821, has been identified in the libssh library. This flaw arises from an insecure default configuration on Windows systems. Specifically, libssh automatically loads configuration files from the `C:\etc` directory. Critically, this directory can be created and modified by unprivileged local users. This allows a malicious local user to manipulate the SSH configuration, facilitating man-in-the-middle attacks, downgrading connection security, and manipulating…
