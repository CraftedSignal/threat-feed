---
title: UniFi Play Improper Access Control Allows SSH Enablement
slug: 2026-04-unifi-play-ssh-enable
description: CVE-2026-22564 is an improper access control vulnerability in UniFi Play PowerAmp and Audio Port devices that allows an attacker with network access to enable SSH and make unauthorized system changes.
date: "2026-04-13T22:16:28Z"
severities:
  - critical
tags:
  - cve-2026-22564
  - unifi-play
  - access-control
  - ssh
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-22564
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-22564
  - https://community.ui.com/releases/Security-Advisory-Bulletin-063/e468dd4b-5090-4ef8-89d8-939903c08e83
ioc_counts:
  email: 1
rules:
  - title: Detect SSH Login to UniFi Play Devices
    description: Detects successful SSH login events to UniFi Play devices, potentially indicating exploitation of CVE-2026-22564.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1078
    data_sources:
      - network_connection
      - linux
  - title: Detect Unauthorized Process Creation on UniFi Play via SSH
    description: Detects unusual process creation on UniFi Play devices following a potential SSH compromise.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

CVE-2026-22564 is a critical vulnerability affecting UniFi Play PowerAmp (version 1.0.35 and earlier) and UniFi Play Audio Port (version 1.0.24 and earlier) devices. This improper access control flaw allows a malicious actor, who has already gained access to the UniFi Play network, to enable SSH access on the affected devices. This unauthorized SSH access can then be leveraged to make arbitrary changes to the system configuration, potentially leading to full device compromise and further…
