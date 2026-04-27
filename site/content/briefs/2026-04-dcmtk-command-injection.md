---
title: OFFIS DCMTK Command Injection Vulnerability (CVE-2026-5663)
slug: 2026-04-dcmtk-command-injection
description: A remote command injection vulnerability exists in OFFIS DCMTK version 3.7.0 and earlier due to insufficient input sanitization in the `storescp` application, potentially allowing unauthenticated attackers to execute arbitrary OS commands.
date: "2026-04-06T15:17:16Z"
severities:
  - high
tags:
  - command-injection
  - dcmtk
  - cve-2026-5663
  - storescp
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-5663
    cvss: 7.3
    epss: 0.01761
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5663
  - https://github.com/DCMTK/dcmtk/commit/edbb085e45788dccaf0e64d71534cfca925784b8
  - https://vuldb.com/vuln/355486
rules:
  - title: Suspicious Processes Spawned by storescp
    description: Detects suspicious processes spawned by the storescp application, indicative of command injection exploitation.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: DCMTK storescp Network Connection to Uncommon Ports
    description: Detects network connections from storescp to uncommon ports, possibly indicating command and control activity after exploitation.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

A command injection vulnerability, identified as CVE-2026-5663, affects OFFIS DCMTK (Dicom ToolKit) versions up to 3.7.0. The vulnerability is located within the `storescp` application, specifically in the `executeOnReception` and `executeOnEndOfStudy` functions of the `dcmnet/apps/storescp.cc` file. An attacker can exploit this flaw by manipulating input parameters processed by these functions, leading to arbitrary OS command execution on the server. Remote exploitation is possible, making…
