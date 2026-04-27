---
title: NVIDIA DALI Deserialization Vulnerability (CVE-2026-24156)
slug: 2026-04-nvidia-dali-deserialization
description: NVIDIA DALI contains a deserialization of untrusted data vulnerability, identified as CVE-2026-24156, which may lead to arbitrary code execution.
date: "2026-04-07T18:16:39Z"
severities:
  - high
tags:
  - cve-2026-24156
  - deserialization
  - nvidia
  - dali
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1202
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-24156
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-24156
  - https://nvidia.custhelp.com/app/answers/detail/a_id/5811
  - https://www.cve.org/CVERecord?id=CVE-2026-24156
ioc_counts:
  email: 1
rules:
  - title: Detect DALI Process Spawning Suspicious Child Processes
    description: Detects instances where DALI spawns child processes indicative of potential exploitation.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect DALI Deserialization via Command Line
    description: Detects suspicious command-line arguments passed to DALI indicating potential deserialization attempts.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1202
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

CVE-2026-24156 describes a deserialization of untrusted data vulnerability within NVIDIA DALI. This vulnerability could allow an attacker to execute arbitrary code on a vulnerable system. According to NVIDIA's advisory, a successful exploit requires local access, a low level of privileges, and user interaction. The CVSS v3.1 score is rated as 7.3 (HIGH). The vulnerability was reported on April 7, 2026. Successful exploitation could allow an attacker to compromise the confidentiality, integrity…
