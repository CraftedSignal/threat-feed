---
title: cPanel/WHM Local Privilege Escalation Vulnerability
slug: 2024-05-cpanel-privesc
description: A local attacker can exploit a vulnerability in cPanel/WHM to escalate their privileges.
date: "2026-04-01T09:24:03Z"
severities:
  - high
tags:
  - privilege-escalation
  - cpanel
  - whm
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2025-2710
rules:
  - title: Suspicious Process Spawned by cPanel Binaries
    description: Detects unexpected processes spawned by cPanel binaries, which could indicate privilege escalation.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
  - title: cPanel File Modification by Unexpected User
    description: Detects file modifications within cPanel directories by users other than 'root' or 'cpanel'.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - file_event
      - linux
rules_count: 2
---

A vulnerability exists in cPanel/WHM that allows a local attacker to escalate their privileges on the system. While the specific details of the vulnerability are not provided in the source, the core issue lies within the cPanel/WHM software suite. This could allow an attacker with limited access to gain root privileges. Defenders should focus on detecting suspicious activity indicative of privilege escalation attempts following successful initial access. The vulnerability has been disclosed in…
