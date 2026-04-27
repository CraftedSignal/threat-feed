---
title: PInfo 0.6.9-5.1 Local Buffer Overflow Vulnerability
slug: 2024-01-pinfo-buffer-overflow
description: PInfo version 0.6.9-5.1 is susceptible to a local buffer overflow vulnerability, enabling local attackers to execute arbitrary code by providing an overly large argument to the '-m' parameter, ultimately allowing for shellcode execution with user privileges.
date: "2026-03-28T12:16:00Z"
severities:
  - high
tags:
  - buffer-overflow
  - local-privilege-escalation
  - cve-2016-20044
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2016-20044
  - http://pinfo.alioth.debian.org/
  - https://www.exploit-db.com/exploits/40023
  - https://www.vulncheck.com/advisories/pinfo-local-buffer-overflow-via-m-parameter
rules:
  - title: Detect PInfo Buffer Overflow Attempt via Long Argument
    description: Detects potential buffer overflow attempts in PInfo by monitoring for unusually long arguments passed to the -m parameter.
    platform: sigma
    severity: high
    tactics:
      - execution
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
  - title: Detect PInfo Execution from /tmp directory
    description: Detects potential exploitation attempts by monitoring for PInfo execution from the /tmp directory, which is often used for storing malicious payloads.
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

PInfo 0.6.9-5.1 contains a critical local buffer overflow vulnerability (CVE-2016-20044) that allows a malicious local attacker to execute arbitrary code. This vulnerability stems from the application's insufficient input validation when handling the '-m' parameter. By exploiting this flaw, an attacker can overwrite the instruction pointer and gain unauthorized access. This can potentially lead to full system compromise. The attacker crafts a malicious input string with 564 bytes of padding…
