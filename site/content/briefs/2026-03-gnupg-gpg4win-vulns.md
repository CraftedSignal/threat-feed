---
title: Multiple Vulnerabilities in GnuPG and Gpg4win Allow for Arbitrary Code Execution and Denial of Service
slug: 2026-03-gnupg-gpg4win-vulns
description: Multiple vulnerabilities exist in GnuPG and Gpg4win that could allow a remote attacker to execute arbitrary code or cause a denial-of-service condition.
date: "2026-03-25T12:00:00Z"
severities:
  - critical
tags:
  - gnupg
  - gpg4win
  - vulnerability
  - code-execution
  - denial-of-service
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-0231
rules:
  - title: Detect Suspicious Processes Spawning from GnuPG or Gpg4win
    description: Detects suspicious child processes spawned from GnuPG or Gpg4win, which may indicate exploitation leading to code execution.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
  - title: Detect GnuPG or Gpg4win Crash Events
    description: Detects crash events associated with GnuPG or Gpg4win processes, potentially indicating a denial-of-service vulnerability exploitation.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499.001
    data_sources:
      - application
      - windows
rules_count: 2
---

GnuPG (GNU Privacy Guard) is a widely used open-source software suite for cryptographic privacy and data security, commonly used for encrypting and signing data and communications. Gpg4win (GNU Privacy Guard for Windows) is a software package that integrates GnuPG with the Windows operating system. According to a recent advisory published March 24, 2026, multiple unspecified vulnerabilities exist within both GnuPG and Gpg4win. Successful exploitation of these vulnerabilities could allow an…
