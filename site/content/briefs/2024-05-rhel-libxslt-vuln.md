---
title: Red Hat Enterprise Linux libxslt Vulnerability Allows DoS and Code Execution
slug: 2024-05-rhel-libxslt-vuln
description: A local attacker can exploit a vulnerability in libxslt on Red Hat Enterprise Linux to cause a denial of service or execute arbitrary program code.
date: "2026-04-01T09:20:35Z"
severities:
  - critical
tags:
  - libxslt
  - rhel
  - vulnerability
  - code-execution
  - denial-of-service
  - linux
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2025-0718
rules:
  - title: Detect Suspicious Child Processes from Libxslt
    description: Detects suspicious child processes spawned by applications utilizing the libxslt library, which could indicate code execution following exploitation of a vulnerability.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect Execution of Scripts in /tmp by Unlikely Programs
    description: Detects the execution of scripts in /tmp by programs other than those typically used to execute scripts. This could be caused by code-execution after an exploit.
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

A vulnerability exists in the libxslt library within Red Hat Enterprise Linux (RHEL) that could allow a local attacker to perform a denial-of-service (DoS) attack or execute arbitrary code. While specific versions and CVEs are not mentioned in the advisory, the potential impact is significant. This vulnerability could be exploited if a user processes a malicious XSLT stylesheet, leading to memory corruption or other exploitable conditions. This poses a serious risk to systems where libxslt is…
