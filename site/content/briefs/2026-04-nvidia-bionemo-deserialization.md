---
title: NVIDIA BioNeMo Deserialization Vulnerability (CVE-2026-24164)
slug: 2026-04-nvidia-bionemo-deserialization
description: NVIDIA BioNeMo is vulnerable to deserialization of untrusted data (CVE-2026-24164), potentially leading to code execution, denial of service, information disclosure, and data tampering.
date: "2026-03-31T17:17:41Z"
severities:
  - high
tags:
  - cve
  - deserialization
  - nvidia
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-24164
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-24164
  - https://nvidia.custhelp.com/app/answers/detail/a_id/5808
  - https://www.cve.org/CVERecord?id=CVE-2026-24164
ioc_counts:
  email: 1
rules:
  - title: Detect Suspicious BioNeMo Deserialization Attempts
    description: Detects suspicious POST requests potentially exploiting deserialization vulnerabilities in NVIDIA BioNeMo.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect BioNeMo Child Process
    description: Detects suspicious child processes spawned by the BioNeMo application.
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

A deserialization of untrusted data vulnerability has been identified in NVIDIA BioNeMo (CVE-2026-24164). This vulnerability allows a malicious actor to potentially inject arbitrary code, trigger a denial-of-service condition, expose sensitive information, or tamper with data within the BioNeMo environment. The vulnerability stems from BioNeMo's processing of serialized data, which, if crafted maliciously, can lead to unintended code execution or system compromise. The reported CVSS v3.1 score…
